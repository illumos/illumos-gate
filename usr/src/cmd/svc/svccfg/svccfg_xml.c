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

#include <libxml/parser.h>
#include <libxml/xinclude.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <libuutil.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "svccfg.h"

/*
 * XML document manipulation routines
 *
 * These routines provide translation to and from the internal representation to
 * XML.  Directionally-oriented verbs are with respect to the external source,
 * so lxml_get_service() fetches a service from the XML file into the
 * internal representation.
 */

const char * const delete_attr = "delete";
const char * const enabled_attr = "enabled";
const char * const name_attr = "name";
const char * const override_attr = "override";
const char * const type_attr = "type";
const char * const value_attr = "value";
const char * const true = "true";
const char * const false = "false";

/*
 * The following list must be kept in the same order as that of
 * element_t array
 */
static const char *lxml_elements[] = {
	"astring_list",			/* SC_ASTRING */
	"boolean_list",			/* SC_BOOLEAN */
	"common_name",			/* SC_COMMON_NAME */
	"count_list",			/* SC_COUNT */
	"create_default_instance",	/* SC_INSTANCE_CREATE_DEFAULT */
	"dependency",			/* SC_DEPENDENCY */
	"dependent",			/* SC_DEPENDENT */
	"description",			/* SC_DESCRIPTION */
	"doc_link",			/* SC_DOC_LINK */
	"documentation",		/* SC_DOCUMENTATION */
	"enabled",			/* SC_ENABLED */
	"exec_method",			/* SC_EXEC_METHOD */
	"fmri_list",			/* SC_FMRI */
	"host_list",			/* SC_HOST */
	"hostname_list",		/* SC_HOSTNAME */
	"instance",			/* SC_INSTANCE */
	"integer_list",			/* SC_INTEGER */
	"loctext",			/* SC_LOCTEXT */
	"manpage",			/* SC_MANPAGE */
	"method_context",		/* SC_METHOD_CONTEXT */
	"method_credential",		/* SC_METHOD_CREDENTIAL */
	"method_profile",		/* SC_METHOD_PROFILE */
	"method_environment",		/* SC_METHOD_ENVIRONMENT */
	"envvar",			/* SC_METHOD_ENVVAR */
	"net_address_v4_list",		/* SC_NET_ADDR_V4 */
	"net_address_v6_list",		/* SC_NET_ADDR_V6 */
	"opaque_list",			/* SC_OPAQUE */
	"property",			/* SC_PROPERTY */
	"property_group",		/* SC_PROPERTY_GROUP */
	"propval",			/* SC_PROPVAL */
	"restarter",			/* SC_RESTARTER */
	"service",			/* SC_SERVICE */
	"service_bundle",		/* SC_SERVICE_BUNDLE */
	"service_fmri",			/* SC_SERVICE_FMRI */
	"single_instance",		/* SC_INSTANCE_SINGLE */
	"stability",			/* SC_STABILITY */
	"template",			/* SC_TEMPLATE */
	"time_list",			/* SC_TIME */
	"uri_list",			/* SC_URI */
	"ustring_list",			/* SC_USTRING */
	"value_node",			/* SC_VALUE_NODE */
	"xi:fallback",			/* SC_XI_FALLBACK */
	"xi:include"			/* SC_XI_INCLUDE */
};

/*
 * The following list must be kept in the same order as that of
 * element_t array
 */
static const char *lxml_prop_types[] = {
	"astring",			/* SC_ASTRING */
	"boolean",			/* SC_BOOLEAN */
	"",				/* SC_COMMON_NAME */
	"count",			/* SC_COUNT */
	"",				/* SC_INSTANCE_CREATE_DEFAULT */
	"",				/* SC_DEPENDENCY */
	"",				/* SC_DEPENDENT */
	"",				/* SC_DESCRIPTION */
	"",				/* SC_DOC_LINK */
	"",				/* SC_DOCUMENTATION */
	"",				/* SC_ENABLED */
	"",				/* SC_EXEC_METHOD */
	"fmri",				/* SC_FMRI */
	"host",				/* SC_HOST */
	"hostname",			/* SC_HOSTNAME */
	"",				/* SC_INSTANCE */
	"integer",			/* SC_INTEGER */
	"",				/* SC_LOCTEXT */
	"",				/* SC_MANPAGE */
	"",				/* SC_METHOD_CONTEXT */
	"",				/* SC_METHOD_CREDENTIAL */
	"",				/* SC_METHOD_PROFILE */
	"",				/* SC_METHOD_ENVIRONMENT */
	"",				/* SC_METHOD_ENVVAR */
	"net_address_v4",		/* SC_NET_ADDR_V4 */
	"net_address_v6",		/* SC_NET_ADDR_V6 */
	"opaque",			/* SC_OPAQUE */
	"",				/* SC_PROPERTY */
	"",				/* SC_PROPERTY_GROUP */
	"",				/* SC_PROPVAL */
	"",				/* SC_RESTARTER */
	"",				/* SC_SERVICE */
	"",				/* SC_SERVICE_BUNDLE */
	"",				/* SC_SERVICE_FMRI */
	"",				/* SC_INSTANCE_SINGLE */
	"",				/* SC_STABILITY */
	"",				/* SC_TEMPLATE */
	"time",				/* SC_TIME */
	"uri",				/* SC_URI */
	"ustring",			/* SC_USTRING */
	""				/* SC_VALUE_NODE */
	""				/* SC_XI_FALLBACK */
	""				/* SC_XI_INCLUDE */
};

int
lxml_init()
{
	if (getenv("SVCCFG_NOVALIDATE") == NULL) {
		/*
		 * DTD validation, with line numbers.
		 */
		xmlLineNumbersDefault(1);
		xmlLoadExtDtdDefaultValue |= XML_DETECT_IDS;
		xmlLoadExtDtdDefaultValue |= XML_COMPLETE_ATTRS;
	}

	return (0);
}

static bundle_type_t
lxml_xlate_bundle_type(xmlChar *type)
{
	if (xmlStrcmp(type, (const xmlChar *)"manifest") == 0)
		return (SVCCFG_MANIFEST);

	if (xmlStrcmp(type, (const xmlChar *)"profile") == 0)
		return (SVCCFG_PROFILE);

	if (xmlStrcmp(type, (const xmlChar *)"archive") == 0)
		return (SVCCFG_ARCHIVE);

	return (SVCCFG_UNKNOWN_BUNDLE);
}

static service_type_t
lxml_xlate_service_type(xmlChar *type)
{
	if (xmlStrcmp(type, (const xmlChar *)"service") == 0)
		return (SVCCFG_SERVICE);

	if (xmlStrcmp(type, (const xmlChar *)"restarter") == 0)
		return (SVCCFG_RESTARTER);

	if (xmlStrcmp(type, (const xmlChar *)"milestone") == 0)
		return (SVCCFG_MILESTONE);

	return (SVCCFG_UNKNOWN_SERVICE);
}

static element_t
lxml_xlate_element(const xmlChar *tag)
{
	int i;

	for (i = 0; i < sizeof (lxml_elements) / sizeof (char *); i++)
		if (xmlStrcmp(tag, (const xmlChar *)lxml_elements[i]) == 0)
			return ((element_t)i);

	return ((element_t)-1);
}

static uint_t
lxml_xlate_boolean(const xmlChar *value)
{
	if (xmlStrcmp(value, (const xmlChar *)true) == 0)
		return (1);

	if (xmlStrcmp(value, (const xmlChar *)false) == 0)
		return (0);

	uu_die(gettext("illegal boolean value \"%s\"\n"), value);

	/*NOTREACHED*/
}

static scf_type_t
lxml_element_to_type(element_t type)
{
	switch (type) {
	case SC_ASTRING:	return (SCF_TYPE_ASTRING);
	case SC_BOOLEAN:	return (SCF_TYPE_BOOLEAN);
	case SC_COUNT:		return (SCF_TYPE_COUNT);
	case SC_FMRI:		return (SCF_TYPE_FMRI);
	case SC_HOST:		return (SCF_TYPE_HOST);
	case SC_HOSTNAME:	return (SCF_TYPE_HOSTNAME);
	case SC_INTEGER:	return (SCF_TYPE_INTEGER);
	case SC_NET_ADDR_V4:	return (SCF_TYPE_NET_ADDR_V4);
	case SC_NET_ADDR_V6:	return (SCF_TYPE_NET_ADDR_V6);
	case SC_OPAQUE:		return (SCF_TYPE_OPAQUE);
	case SC_TIME:		return (SCF_TYPE_TIME);
	case SC_URI:		return (SCF_TYPE_URI);
	case SC_USTRING:	return (SCF_TYPE_USTRING);

	default:
		uu_die(gettext("unknown value type (%d)\n"), type);
	}

	/* NOTREACHED */
}

static scf_type_t
lxml_element_to_scf_type(element_t type)
{
	switch (type) {
	case SC_ASTRING:	return (SCF_TYPE_ASTRING);
	case SC_BOOLEAN:	return (SCF_TYPE_BOOLEAN);
	case SC_COUNT:		return (SCF_TYPE_COUNT);
	case SC_FMRI:		return (SCF_TYPE_FMRI);
	case SC_HOST:		return (SCF_TYPE_HOST);
	case SC_HOSTNAME:	return (SCF_TYPE_HOSTNAME);
	case SC_INTEGER:	return (SCF_TYPE_INTEGER);
	case SC_NET_ADDR_V4:	return (SCF_TYPE_NET_ADDR_V4);
	case SC_NET_ADDR_V6:	return (SCF_TYPE_NET_ADDR_V6);
	case SC_OPAQUE:		return (SCF_TYPE_OPAQUE);
	case SC_TIME:		return (SCF_TYPE_TIME);
	case SC_URI:		return (SCF_TYPE_URI);
	case SC_USTRING:	return (SCF_TYPE_USTRING);
	default:
		uu_die(gettext("unknown value type (%d)\n"), type);
	}

	/* NOTREACHED */
}

static int
new_str_prop_from_attr(pgroup_t *pgrp, const char *pname, scf_type_t ty,
    xmlNodePtr n, const char *attr)
{
	xmlChar *val;
	property_t *p;
	int r;

	val = xmlGetProp(n, (xmlChar *)attr);

	p = internal_property_create(pname, ty, 1, val);
	r = internal_attach_property(pgrp, p);

	if (r != 0)
		internal_property_free(p);

	return (r);
}

static int
lxml_ignorable_block(xmlNodePtr n)
{
	return ((xmlStrcmp(n->name, (xmlChar *)"text") == 0 ||
	    xmlStrcmp(n->name, (xmlChar *)"comment") == 0) ? 1 : 0);
}

static int
lxml_validate_string_value(scf_type_t type, const char *v)
{
	static scf_value_t *scf_value = NULL;
	static scf_handle_t *scf_hndl = NULL;

	if (scf_hndl == NULL && (scf_hndl = scf_handle_create(SCF_VERSION)) ==
	    NULL)
		return (-1);

	if (scf_value == NULL && (scf_value = scf_value_create(scf_hndl)) ==
	    NULL)
		return (-1);

	return (scf_value_set_from_string(scf_value, type, v));
}

static void
lxml_free_str(value_t *val)
{
	free(val->sc_u.sc_string);
}

static value_t *
lxml_make_value(element_t type, const xmlChar *value)
{
	value_t *v;
	char *endptr;
	scf_type_t scf_type = SCF_TYPE_INVALID;

	v = internal_value_new();

	v->sc_type = lxml_element_to_type(type);

	switch (type) {
	case SC_COUNT:
		/*
		 * Although an SC_COUNT represents a uint64_t the use
		 * of a negative value is acceptable due to the usage
		 * established by inetd(1M).
		 */
		errno = 0;
		v->sc_u.sc_count = strtoull((char *)value, &endptr, 10);
		if (errno != 0 || endptr == (char *)value || *endptr)
			uu_die(gettext("illegal value \"%s\" for "
			    "%s (%s)\n"), (char *)value,
			    lxml_prop_types[type],
			    (errno) ? strerror(errno) :
			    gettext("Illegal character"));
		break;
	case SC_INTEGER:
		errno = 0;
		v->sc_u.sc_integer = strtoll((char *)value, &endptr, 10);
		if (errno != 0 || *endptr)
			uu_die(gettext("illegal value \"%s\" for "
			    "%s (%s)\n"), (char *)value,
			    lxml_prop_types[type],
			    (errno) ? strerror(errno) : "Illegal character");
		break;
	case SC_OPAQUE:
	case SC_HOST:
	case SC_HOSTNAME:
	case SC_NET_ADDR_V4:
	case SC_NET_ADDR_V6:
	case SC_FMRI:
	case SC_URI:
	case SC_TIME:
	case SC_ASTRING:
	case SC_USTRING:
		scf_type = lxml_element_to_scf_type(type);

		if ((v->sc_u.sc_string = strdup((char *)value)) == NULL)
			uu_die(gettext("string duplication failed (%s)\n"),
			    strerror(errno));
		if (lxml_validate_string_value(scf_type,
		    v->sc_u.sc_string) != 0)
			uu_die(gettext("illegal value \"%s\" for "
			    "%s (%s)\n"), (char *)value,
			    lxml_prop_types[type],
			    (scf_error()) ? scf_strerror(scf_error()) :
			    gettext("Illegal format"));
		v->sc_free = lxml_free_str;
		break;
	case SC_BOOLEAN:
		v->sc_u.sc_count = lxml_xlate_boolean(value);
		break;
	default:
		uu_die(gettext("unknown value type (%d)\n"), type);
		break;
	}

	return (v);
}

static int
lxml_get_value(property_t *prop, element_t vtype, xmlNodePtr value)
{
	xmlNodePtr cursor;

	for (cursor = value->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		xmlChar *assigned_value;
		value_t *v;

		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_VALUE_NODE:
			if ((assigned_value = xmlGetProp(cursor,
			    (xmlChar *)value_attr)) == NULL)
				uu_die(gettext("no value on value node?\n"));
			break;
		default:
			uu_die(gettext("value list contains illegal element "
			    "\'%s\'\n"), cursor->name);
			break;
		}

		v = lxml_make_value(vtype, assigned_value);

		xmlFree(assigned_value);

		internal_attach_value(prop, v);
	}

	return (0);
}

static int
lxml_get_propval(pgroup_t *pgrp, xmlNodePtr propval)
{
	property_t *p;
	element_t r;
	value_t *v;
	xmlChar *type, *val, *override;

	p = internal_property_new();

	p->sc_property_name = (char *)xmlGetProp(propval, (xmlChar *)name_attr);
	if (p->sc_property_name == NULL)
		uu_die(gettext("property name missing in group '%s'\n"),
		    pgrp->sc_pgroup_name);

	type = xmlGetProp(propval, (xmlChar *)type_attr);
	if (type == NULL)
		uu_die(gettext("property type missing for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);

	for (r = 0; r < sizeof (lxml_prop_types) / sizeof (char *); ++r) {
		if (xmlStrcmp(type, (const xmlChar *)lxml_prop_types[r]) == 0)
			break;
	}
	if (r >= sizeof (lxml_prop_types) / sizeof (char *))
		uu_die(gettext("property type invalid for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);

	p->sc_value_type = lxml_element_to_type(r);

	val = xmlGetProp(propval, (xmlChar *)value_attr);
	if (val == NULL)
		uu_die(gettext("property value missing for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);

	v = lxml_make_value(r, val);
	internal_attach_value(p, v);

	override = xmlGetProp(propval, (xmlChar *)override_attr);
	p->sc_property_override = (xmlStrcmp(override, (xmlChar *)true) == 0);
	xmlFree(override);

	return (internal_attach_property(pgrp, p));
}

static int
lxml_get_property(pgroup_t *pgrp, xmlNodePtr property)
{
	property_t *p;
	xmlNodePtr cursor;
	element_t r;
	xmlChar *type, *override;

	p = internal_property_new();

	if ((p->sc_property_name = (char *)xmlGetProp(property,
	    (xmlChar *)name_attr)) == NULL)
		uu_die(gettext("property name missing in group \'%s\'\n"),
		    pgrp->sc_pgroup_name);

	if ((type = xmlGetProp(property, (xmlChar *)type_attr)) == NULL)
		uu_die(gettext("property type missing for "
		    "property \'%s/%s\'\n"), pgrp->sc_pgroup_name,
		    p->sc_property_name);

	for (r = 0; r < sizeof (lxml_prop_types) / sizeof (char *); r++) {
		if (xmlStrcmp(type, (const xmlChar *)lxml_prop_types[r]) == 0)
			break;
	}

	if (r >= sizeof (lxml_prop_types) / sizeof (char *)) {
		uu_die(gettext("property type invalid for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);
	}

	p->sc_value_type = lxml_element_to_type(r);

	for (cursor = property->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (r = lxml_xlate_element(cursor->name)) {
		case SC_ASTRING:
		case SC_BOOLEAN:
		case SC_COUNT:
		case SC_FMRI:
		case SC_HOST:
		case SC_HOSTNAME:
		case SC_INTEGER:
		case SC_NET_ADDR_V4:
		case SC_NET_ADDR_V6:
		case SC_OPAQUE:
		case SC_TIME:
		case SC_URI:
		case SC_USTRING:
			if (strcmp(lxml_prop_types[r], (const char *)type) != 0)
				uu_die(gettext("property \'%s\' "
				    "type-to-list mismatch\n"),
				    p->sc_property_name);

			(void) lxml_get_value(p, r, cursor);
			break;
		default:
			uu_die(gettext("unknown value list type: %s\n"),
			    cursor->name);
			break;
		}
	}

	xmlFree(type);

	override = xmlGetProp(property, (xmlChar *)override_attr);
	p->sc_property_override = (xmlStrcmp(override, (xmlChar *)true) == 0);
	xmlFree(override);

	return (internal_attach_property(pgrp, p));
}

static int
lxml_get_pgroup_stability(pgroup_t *pgrp, xmlNodePtr stab)
{
	return (new_str_prop_from_attr(pgrp, SCF_PROPERTY_STABILITY,
	    SCF_TYPE_ASTRING, stab, value_attr));
}

/*
 * Property groups can go on any of a service, an instance, or a template.
 */
static int
lxml_get_pgroup(entity_t *entity, xmlNodePtr pgroup)
{
	pgroup_t *pg;
	xmlNodePtr cursor;
	xmlChar *name, *type, *delete;

	/*
	 * property group attributes:
	 * name: string
	 * type: string | framework | application
	 */
	name = xmlGetProp(pgroup, (xmlChar *)name_attr);
	type = xmlGetProp(pgroup, (xmlChar *)type_attr);
	pg = internal_pgroup_find_or_create(entity, (char *)name, (char *)type);
	xmlFree(name);
	xmlFree(type);

	/*
	 * Walk the children of this lxml_elements, which are a stability
	 * element, property elements, or propval elements.
	 */
	for (cursor = pgroup->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_STABILITY:
			(void) lxml_get_pgroup_stability(pg, cursor);
			break;
		case SC_PROPERTY:
			(void) lxml_get_property(pg, cursor);
			break;
		case SC_PROPVAL:
			(void) lxml_get_propval(pg, cursor);
			break;
		default:
			abort();
			break;
		}
	}

	delete = xmlGetProp(pgroup, (xmlChar *)delete_attr);
	pg->sc_pgroup_delete = (xmlStrcmp(delete, (xmlChar *)true) == 0);
	xmlFree(delete);

	return (0);
}


/*
 * Dependency groups, execution methods can go on either a service or an
 * instance.
 */

static int
lxml_get_method_profile(pgroup_t *pg, xmlNodePtr profile)
{
	property_t *p;

	p = internal_property_create(SCF_PROPERTY_USE_PROFILE, SCF_TYPE_BOOLEAN,
	    1, (uint64_t)1);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	return (new_str_prop_from_attr(pg, SCF_PROPERTY_PROFILE,
	    SCF_TYPE_ASTRING, profile, name_attr));
}

static int
lxml_get_method_credential(pgroup_t *pg, xmlNodePtr cred)
{
	property_t *p;

	p = internal_property_create(SCF_PROPERTY_USE_PROFILE, SCF_TYPE_BOOLEAN,
	    1, (uint64_t)0);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_USER, SCF_TYPE_ASTRING,
	    cred, "user") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_GROUP, SCF_TYPE_ASTRING,
	    cred, "group") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_SUPP_GROUPS,
	    SCF_TYPE_ASTRING, cred, "supp_groups") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_PRIVILEGES,
	    SCF_TYPE_ASTRING, cred, "privileges") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_LIMIT_PRIVILEGES,
	    SCF_TYPE_ASTRING, cred, "limit_privileges") != 0)
		return (-1);

	return (0);
}

static char *
lxml_get_envvar(xmlNodePtr envvar)
{
	char *name;
	char *value;
	char *ret;

	name = (char *)xmlGetProp(envvar, (xmlChar *)"name");
	value = (char *)xmlGetProp(envvar, (xmlChar *)"value");

	if (strlen(name) == 0 || strchr(name, '=') != NULL)
		uu_die(gettext("Invalid environment variable "
		    "\"%s\".\n"), name);
	if (strstr(name, "SMF_") == name)
		uu_die(gettext("Invalid environment variable "
		    "\"%s\"; \"SMF_\" prefix is reserved.\n"), name);

	ret = uu_msprintf("%s=%s", name, value);
	xmlFree(name);
	xmlFree(value);
	return (ret);
}

static int
lxml_get_method_environment(pgroup_t *pg, xmlNodePtr environment)
{
	property_t *p;
	xmlNodePtr cursor;
	value_t *val;

	p = internal_property_create(SCF_PROPERTY_ENVIRONMENT,
	    SCF_TYPE_ASTRING, 0);

	for (cursor = environment->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		char *tmp;

		if (lxml_ignorable_block(cursor))
			continue;

		if (lxml_xlate_element(cursor->name) != SC_METHOD_ENVVAR)
			uu_die(gettext("illegal element \"%s\" on "
			    "method environment for \"%s\"\n"),
			    cursor->name, pg->sc_pgroup_name);

		if ((tmp = lxml_get_envvar(cursor)) == NULL)
			uu_die(gettext("Out of memory\n"));

		val = internal_value_new();
		val->sc_u.sc_string = tmp;
		val->sc_type = SCF_TYPE_ASTRING;
		val->sc_free = lxml_free_str;
		internal_attach_value(p, val);
	}

	if (internal_attach_property(pg, p) != 0) {
		internal_property_free(p);
		return (-1);
	}

	return (0);
}

static int
lxml_get_method_context(pgroup_t *pg, xmlNodePtr ctx)
{
	xmlNodePtr cursor;

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_WORKING_DIRECTORY,
	    SCF_TYPE_ASTRING, ctx, "working_directory") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_PROJECT, SCF_TYPE_ASTRING,
	    ctx, "project") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_RESOURCE_POOL,
	    SCF_TYPE_ASTRING, ctx, "resource_pool") != 0)
		return (-1);

	for (cursor = ctx->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_METHOD_CREDENTIAL:
			(void) lxml_get_method_credential(pg, cursor);
			break;
		case SC_METHOD_PROFILE:
			(void) lxml_get_method_profile(pg, cursor);
			break;
		case SC_METHOD_ENVIRONMENT:
			(void) lxml_get_method_environment(pg, cursor);
			break;
		default:
			semerr(gettext("illegal element \'%s\' in method "
			    "context\n"), (char *)cursor);
			break;
		}
	}

	return (0);
}

static int
lxml_get_entity_method_context(entity_t *entity, xmlNodePtr ctx)
{
	pgroup_t *pg;

	pg = internal_pgroup_find_or_create(entity, SCF_PG_METHOD_CONTEXT,
	    (char *)scf_group_framework);

	return (lxml_get_method_context(pg, ctx));
}

static int
lxml_get_exec_method(entity_t *entity, xmlNodePtr emeth)
{
	pgroup_t *pg;
	property_t *p;
	xmlChar *name, *timeout, *delete;
	xmlNodePtr cursor;
	int r = 0;

	name = xmlGetProp(emeth, (xmlChar *)name_attr);
	pg = internal_pgroup_find_or_create(entity, (char *)name,
	    (char *)SCF_GROUP_METHOD);
	xmlFree(name);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_TYPE, SCF_TYPE_ASTRING,
	    emeth, type_attr) != 0 ||
	    new_str_prop_from_attr(pg, SCF_PROPERTY_EXEC, SCF_TYPE_ASTRING,
	    emeth, "exec") != 0)
		return (-1);

	timeout = xmlGetProp(emeth, (xmlChar *)"timeout_seconds");
	if (timeout != NULL) {
		uint64_t u_timeout;
		char *endptr;
		/*
		 * Although an SC_COUNT represents a uint64_t the use
		 * of a negative value is acceptable due to the usage
		 * established by inetd(1M).
		 */
		errno = 0;
		u_timeout = strtoull((char *)timeout, &endptr, 10);
		if (errno != 0 || endptr == (char *)timeout || *endptr)
			uu_die(gettext("illegal value \"%s\" for "
			    "timeout_seconds (%s)\n"),
			    (char *)timeout, (errno) ? strerror(errno):
			    gettext("Illegal character"));
		p = internal_property_create(SCF_PROPERTY_TIMEOUT,
		    SCF_TYPE_COUNT, 1, u_timeout);
		r = internal_attach_property(pg, p);
		xmlFree(timeout);
	}
	if (r != 0)
		return (-1);

	/*
	 * There is a possibility that a method context also exists, in which
	 * case the following attributes are defined: project, resource_pool,
	 * working_directory, profile, user, group, privileges, limit_privileges
	 */
	for (cursor = emeth->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_STABILITY:
			if (lxml_get_pgroup_stability(pg, cursor) != 0)
				return (-1);
			break;

		case SC_METHOD_CONTEXT:
			(void) lxml_get_method_context(pg, cursor);
			break;

		case SC_PROPVAL:
			(void) lxml_get_propval(pg, cursor);
			break;

		case SC_PROPERTY:
			(void) lxml_get_property(pg, cursor);
			break;

		default:
			uu_die(gettext("illegal element \"%s\" on "
			    "execution method \"%s\"\n"), cursor->name,
			    pg->sc_pgroup_name);
			break;
		}
	}

	delete = xmlGetProp(emeth, (xmlChar *)delete_attr);
	pg->sc_pgroup_delete = (xmlStrcmp(delete, (xmlChar *)true) == 0);
	xmlFree(delete);

	return (0);
}

static int
lxml_get_dependency(entity_t *entity, xmlNodePtr dependency)
{
	pgroup_t *pg;
	property_t *p;
	xmlNodePtr cursor;
	xmlChar *name;
	xmlChar *delete;

	/*
	 * dependency attributes:
	 * name: string
	 * grouping: require_all | require_any | exclude_all | optional_all
	 * reset_on: string (error | restart | refresh | none)
	 * type:  service / path /host
	 */

	name = xmlGetProp(dependency, (xmlChar *)name_attr);
	pg = internal_pgroup_find_or_create(entity, (char *)name,
	    (char *)SCF_GROUP_DEPENDENCY);
	xmlFree(name);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_TYPE, SCF_TYPE_ASTRING,
	    dependency, type_attr) != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_RESTART_ON,
	    SCF_TYPE_ASTRING, dependency, "restart_on") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_GROUPING, SCF_TYPE_ASTRING,
	    dependency, "grouping") != 0)
		return (-1);

	p = internal_property_create(SCF_PROPERTY_ENTITIES, SCF_TYPE_FMRI, 0);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	for (cursor = dependency->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		xmlChar *value;
		value_t *v;

		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_STABILITY:
			if (lxml_get_pgroup_stability(pg, cursor) != 0)
				return (-1);
			break;

		case SC_SERVICE_FMRI:
			value = xmlGetProp(cursor, (xmlChar *)value_attr);
			if (value != NULL) {
				if (lxml_validate_string_value(SCF_TYPE_FMRI,
				    (char *)value) != 0)
					uu_die(gettext("illegal value \"%s\" "
					    "for %s (%s)\n"), (char *)value,
					    lxml_prop_types[SC_FMRI],
					    (scf_error()) ?
					    scf_strerror(scf_error()) :
					    gettext("Illegal format"));
				v = internal_value_new();
				v->sc_type = SCF_TYPE_FMRI;
				v->sc_u.sc_string = (char *)value;
				internal_attach_value(p, v);
			}

			break;

		case SC_PROPVAL:
			(void) lxml_get_propval(pg, cursor);
			break;

		case SC_PROPERTY:
			(void) lxml_get_property(pg, cursor);
			break;

		default:
			uu_die(gettext("illegal element \"%s\" on "
			    "dependency group \"%s\"\n"), cursor->name, name);
			break;
		}
	}

	delete = xmlGetProp(dependency, (xmlChar *)delete_attr);
	pg->sc_pgroup_delete = (xmlStrcmp(delete, (xmlChar *)true) == 0);
	xmlFree(delete);

	return (0);
}

/*
 * Dependents are hairy.  They should cause a dependency pg to be created in
 * another service, but we can't do that here; we'll have to wait until the
 * import routines.  So for now we'll add the dependency group that should go
 * in the other service to the entity's dependent list.
 */
static int
lxml_get_dependent(entity_t *entity, xmlNodePtr dependent)
{
	xmlChar *name, *or;
	xmlNodePtr sf;
	xmlChar *fmri, *delete;
	pgroup_t *pg;
	property_t *p;
	xmlNodePtr n;
	char *myfmri;

	name = xmlGetProp(dependent, (xmlChar *)name_attr);

	if (internal_pgroup_find(entity, (char *)name, NULL) != NULL) {
		semerr(gettext("Property group and dependent of entity %s "
		    "have same name \"%s\".\n"), entity->sc_name, name);
		xmlFree(name);
		return (-1);
	}

	or = xmlGetProp(dependent, (xmlChar *)override_attr);

	pg = internal_pgroup_new();
	pg->sc_pgroup_name = (char *)name;
	pg->sc_pgroup_type = (char *)SCF_GROUP_DEPENDENCY;
	pg->sc_pgroup_override = (xmlStrcmp(or, (xmlChar *)true) == 0);
	xmlFree(or);
	if (internal_attach_dependent(entity, pg) != 0) {
		xmlFree(name);
		internal_pgroup_free(pg);
		return (-1);
	}

	for (sf = dependent->children; sf != NULL; sf = sf->next)
		if (xmlStrcmp(sf->name, (xmlChar *)"service_fmri") == 0)
			break;
	assert(sf != NULL);
	fmri = xmlGetProp(sf, (xmlChar *)value_attr);
	pg->sc_pgroup_fmri = (char *)fmri;

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_RESTART_ON,
	    SCF_TYPE_ASTRING, dependent, "restart_on") != 0)
		return (-1);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_GROUPING, SCF_TYPE_ASTRING,
	    dependent, "grouping") != 0)
		return (-1);

	myfmri = safe_malloc(max_scf_fmri_len + 1);
	if (entity->sc_etype == SVCCFG_SERVICE_OBJECT) {
		if (snprintf(myfmri, max_scf_fmri_len + 1, "svc:/%s",
		    entity->sc_name) < 0)
			bad_error("snprintf", errno);
	} else {
		assert(entity->sc_etype == SVCCFG_INSTANCE_OBJECT);
		if (snprintf(myfmri, max_scf_fmri_len + 1, "svc:/%s:%s",
		    entity->sc_parent->sc_name, entity->sc_name) < 0)
			bad_error("snprintf", errno);
	}

	p = internal_property_create(SCF_PROPERTY_ENTITIES, SCF_TYPE_FMRI, 1,
	    myfmri);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	/* Create a property to serve as a do-not-export flag. */
	p = internal_property_create("external", SCF_TYPE_BOOLEAN, 1,
	    (uint64_t)1);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	for (n = sf->next; n != NULL; n = n->next) {
		if (lxml_ignorable_block(n))
			continue;

		switch (lxml_xlate_element(n->name)) {
		case SC_STABILITY:
			if (new_str_prop_from_attr(pg,
			    SCF_PROPERTY_ENTITY_STABILITY, SCF_TYPE_ASTRING, n,
			    value_attr) != 0)
				return (-1);
			break;

		case SC_PROPVAL:
			(void) lxml_get_propval(pg, n);
			break;

		case SC_PROPERTY:
			(void) lxml_get_property(pg, n);
			break;

		default:
			uu_die(gettext("unexpected element %s.\n"), n->name);
		}
	}

	/* Go back and fill in defaults. */
	if (internal_property_find(pg, SCF_PROPERTY_TYPE) == NULL) {
		p = internal_property_create(SCF_PROPERTY_TYPE,
		    SCF_TYPE_ASTRING, 1, "service");
		if (internal_attach_property(pg, p) != 0)
			return (-1);
	}

	delete = xmlGetProp(dependent, (xmlChar *)delete_attr);
	pg->sc_pgroup_delete = (xmlStrcmp(delete, (xmlChar *)true) == 0);
	xmlFree(delete);

	pg = internal_pgroup_find_or_create(entity, "dependents",
	    (char *)scf_group_framework);
	p = internal_property_create((char *)name, SCF_TYPE_FMRI, 1, fmri);
	if (internal_attach_property(pg, p) != 0)
		return (-1);

	return (0);
}

static int
lxml_get_entity_stability(entity_t *entity, xmlNodePtr rstr)
{
	pgroup_t *pg;
	property_t *p;
	xmlChar *stabval;

	if ((stabval = xmlGetProp(rstr, (xmlChar *)value_attr)) == NULL) {
		uu_warn(gettext("no stability value found\n"));
		stabval = (xmlChar *)strdup("External");
	}

	pg = internal_pgroup_find_or_create(entity, (char *)scf_pg_general,
	    (char *)scf_group_framework);

	p = internal_property_create(SCF_PROPERTY_ENTITY_STABILITY,
	    SCF_TYPE_ASTRING, 1, stabval);

	return (internal_attach_property(pg, p));
}

static int
lxml_get_restarter(entity_t *entity, xmlNodePtr rstr)
{
	pgroup_t *pg;
	property_t *p;
	xmlChar *restarter;
	xmlNode *cursor;
	int r;

	/*
	 * Go find child.  Child is a service_fmri element.  value attribute
	 * contains restarter FMRI.
	 */

	pg = internal_pgroup_find_or_create(entity, (char *)scf_pg_general,
	    (char *)scf_group_framework);

	/*
	 * Walk its child elements, as appropriate.
	 */
	for (cursor = rstr->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_SERVICE_FMRI:
			restarter = xmlGetProp(cursor, (xmlChar *)value_attr);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on restarter "
			    "element for \"%s\"\n"), cursor->name,
			    entity->sc_name);
			break;
		}
	}

	p = internal_property_create(SCF_PROPERTY_RESTARTER, SCF_TYPE_FMRI, 1,
	    restarter);

	r = internal_attach_property(pg, p);
	if (r != 0) {
		internal_property_free(p);
		return (-1);
	}

	return (0);
}

static void
sanitize_locale(uchar_t *locale)
{
	for (; *locale != '\0'; locale++)
		if (!isalnum(*locale) && *locale != '_')
			*locale = '_';
}

static int
lxml_get_loctext(entity_t *service, pgroup_t *pg, xmlNodePtr loctext)
{
	xmlNodePtr cursor;
	xmlChar *val;
	char *stripped, *cp;
	property_t *p;
	int r;

	if ((val = xmlGetProp(loctext, (xmlChar *)"xml:lang")) == NULL)
		if ((val = xmlGetProp(loctext, (xmlChar *)"lang")) == NULL)
			val = (xmlChar *)"unknown";

	sanitize_locale(val);

	for (cursor = loctext->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (strcmp("text", (const char *)cursor->name) == 0) {
			break;
		} else if (strcmp("comment", (const char *)cursor->name) != 0) {
			uu_die(gettext("illegal element \"%s\" on loctext "
			    "element for \"%s\"\n"), cursor->name,
			    service->sc_name);
		}
	}

	if (cursor == NULL) {
		uu_die(gettext("loctext element has no content for \"%s\"\n"),
		    service->sc_name);
	}

	/*
	 * Remove leading and trailing whitespace.
	 */
	if ((stripped = strdup((const char *)cursor->content)) == NULL)
		uu_die(gettext("Out of memory\n"));

	for (; isspace(*stripped); stripped++)
		;
	for (cp = stripped + strlen(stripped) - 1; isspace(*cp); cp--)
		;
	*(cp + 1) = '\0';

	p = internal_property_create((const char *)val, SCF_TYPE_USTRING, 1,
	    stripped);

	r = internal_attach_property(pg, p);
	if (r != 0)
		internal_property_free(p);

	return (r);
}

static int
lxml_get_tm_common_name(entity_t *service, xmlNodePtr common_name)
{
	xmlNodePtr cursor;
	pgroup_t *pg;

	/*
	 * Create the property group, if absent.
	 */
	pg = internal_pgroup_find_or_create(service,
	    (char *)SCF_PG_TM_COMMON_NAME, (char *)SCF_GROUP_TEMPLATE);

	/*
	 * Iterate through one or more loctext elements.  The locale is the
	 * property name; the contents are the ustring value for the property.
	 */
	for (cursor = common_name->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_LOCTEXT:
			if (lxml_get_loctext(service, pg, cursor))
				return (-1);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on common_name "
			    "element for \"%s\"\n"), cursor->name,
			    service->sc_name);
			break;
		}
	}

	return (0);
}

static int
lxml_get_tm_description(entity_t *service, xmlNodePtr description)
{
	xmlNodePtr cursor;
	pgroup_t *pg;

	/*
	 * Create the property group, if absent.
	 */
	pg = internal_pgroup_find_or_create(service,
	    (char *)SCF_PG_TM_DESCRIPTION, (char *)SCF_GROUP_TEMPLATE);

	/*
	 * Iterate through one or more loctext elements.  The locale is the
	 * property name; the contents are the ustring value for the property.
	 */
	for (cursor = description->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_LOCTEXT:
			if (lxml_get_loctext(service, pg, cursor))
				return (-1);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on description "
			    "element for \"%s\"\n"), cursor->name,
			    service->sc_name);
			break;
		}
	}

	return (0);
}

static char *
lxml_label_to_groupname(const char *prefix, const char *in)
{
	char *out, *cp;
	size_t len, piece_len;

	out = uu_zalloc(2 * scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1);
	if (out == NULL)
		return (NULL);

	(void) strcpy(out, prefix);
	(void) strcat(out, in);

	len = strlen(out);
	if (len > max_scf_name_len) {
		/* Use the first half and the second half. */
		piece_len = (max_scf_name_len - 2) / 2;

		(void) strncpy(out + piece_len, "..", 2);

		(void) strcpy(out + piece_len + 2, out + (len - piece_len));

		len = strlen(out);
	}

	/*
	 * Translate non-property characters to '_'.
	 */
	for (cp = out; *cp != '\0'; ++cp) {
		if (!(isalnum(*cp) || *cp == '_' || *cp == '-'))
			*cp = '_';
	}

	*cp = '\0';

	return (out);
}

static int
lxml_get_tm_manpage(entity_t *service, xmlNodePtr manpage)
{
	pgroup_t *pg;
	char *pgname;
	xmlChar *title;

	/*
	 * Fetch title attribute, convert to something sanitized, and create
	 * property group.
	 */
	title = xmlGetProp(manpage, (xmlChar *)"title");
	pgname = (char *)lxml_label_to_groupname(SCF_PG_TM_MAN_PREFIX,
	    (const char *)title);

	pg = internal_pgroup_find_or_create(service, pgname,
	    (char *)SCF_GROUP_TEMPLATE);

	/*
	 * Each attribute is an astring property within the group.
	 */
	if (new_str_prop_from_attr(pg, "title", SCF_TYPE_ASTRING, manpage,
	    "title") != 0 ||
	    new_str_prop_from_attr(pg, "section", SCF_TYPE_ASTRING, manpage,
	    "section") != 0 ||
	    new_str_prop_from_attr(pg, "manpath", SCF_TYPE_ASTRING, manpage,
	    "manpath") != 0)
		return (-1);

	return (0);
}

static int
lxml_get_tm_doclink(entity_t *service, xmlNodePtr doc_link)
{
	pgroup_t *pg;
	char *pgname;
	xmlChar *name;

	/*
	 * Fetch name attribute, convert name to something sanitized, and create
	 * property group.
	 */
	name = xmlGetProp(doc_link, (xmlChar *)"name");

	pgname = (char *)lxml_label_to_groupname(SCF_PG_TM_DOC_PREFIX,
	    (const char *)name);

	pg = internal_pgroup_find_or_create(service, pgname,
	    (char *)SCF_GROUP_TEMPLATE);

	/*
	 * Each attribute is an astring property within the group.
	 */
	if (new_str_prop_from_attr(pg, "name", SCF_TYPE_ASTRING, doc_link,
	    "name") != 0 ||
	    new_str_prop_from_attr(pg, "uri", SCF_TYPE_ASTRING, doc_link,
	    "uri") != 0)
		return (-1);

	return (0);
}

static int
lxml_get_tm_documentation(entity_t *service, xmlNodePtr documentation)
{
	xmlNodePtr cursor;

	for (cursor = documentation->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_MANPAGE:
			(void) lxml_get_tm_manpage(service, cursor);
			break;
		case SC_DOC_LINK:
			(void) lxml_get_tm_doclink(service, cursor);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on template "
			    "for service \"%s\"\n"),
			    cursor->name, service->sc_name);
		}
	}

	return (0);
}

static int
lxml_get_template(entity_t *service, xmlNodePtr templ)
{
	xmlNodePtr cursor;

	for (cursor = templ->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_COMMON_NAME:
			(void) lxml_get_tm_common_name(service, cursor);
			break;
		case SC_DESCRIPTION:
			(void) lxml_get_tm_description(service, cursor);
			break;
		case SC_DOCUMENTATION:
			(void) lxml_get_tm_documentation(service, cursor);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on template "
			    "for service \"%s\"\n"),
			    cursor->name, service->sc_name);
		}
	}

	return (0);
}

static int
lxml_get_default_instance(entity_t *service, xmlNodePtr definst)
{
	entity_t *i;
	xmlChar *enabled;
	pgroup_t *pg;
	property_t *p;
	char *package;
	uint64_t enabled_val = 0;

	i = internal_instance_new("default");

	if ((enabled = xmlGetProp(definst, (xmlChar *)enabled_attr)) != NULL) {
		enabled_val = (strcmp(true, (const char *)enabled) == 0) ?
		    1 : 0;
		xmlFree(enabled);
	}

	/*
	 * New general property group with enabled boolean property set.
	 */

	pg = internal_pgroup_new();
	(void) internal_attach_pgroup(i, pg);

	pg->sc_pgroup_name = (char *)scf_pg_general;
	pg->sc_pgroup_type = (char *)scf_group_framework;
	pg->sc_pgroup_flags = 0;

	p = internal_property_create(SCF_PROPERTY_ENABLED, SCF_TYPE_BOOLEAN, 1,
	    enabled_val);

	(void) internal_attach_property(pg, p);

	/*
	 * Add general/package property if PKGINST is set.
	 */
	if ((package = getenv("PKGINST")) != NULL) {
		p = internal_property_create(SCF_PROPERTY_PACKAGE,
		    SCF_TYPE_ASTRING, 1, package);

		(void) internal_attach_property(pg, p);
	}

	return (internal_attach_entity(service, i));
}

/*
 * Translate an instance element into an internal property tree, added to
 * service.  If op is SVCCFG_OP_APPLY (i.e., apply a profile), forbid
 * subelements and set the enabled property to override.
 */
static int
lxml_get_instance(entity_t *service, xmlNodePtr inst, svccfg_op_t op)
{
	entity_t *i;
	pgroup_t *pg;
	property_t *p;
	xmlNodePtr cursor;
	xmlChar *enabled;
	int r;

	/*
	 * Fetch its attributes, as appropriate.
	 */
	i = internal_instance_new((char *)xmlGetProp(inst,
	    (xmlChar *)name_attr));

	/*
	 * Note that this must be done before walking the children so that
	 * sc_fmri is set in case we enter lxml_get_dependent().
	 */
	r = internal_attach_entity(service, i);
	if (r != 0)
		return (r);

	enabled = xmlGetProp(inst, (xmlChar *)enabled_attr);

	/*
	 * New general property group with enabled boolean property set.
	 */
	pg = internal_pgroup_new();
	(void) internal_attach_pgroup(i, pg);

	pg->sc_pgroup_name = (char *)scf_pg_general;
	pg->sc_pgroup_type = (char *)scf_group_framework;
	pg->sc_pgroup_flags = 0;

	p = internal_property_create(SCF_PROPERTY_ENABLED, SCF_TYPE_BOOLEAN, 1,
	    (uint64_t)(strcmp(true, (const char *)enabled) == 0 ? 1 : 0));

	p->sc_property_override = (op == SVCCFG_OP_APPLY);

	(void) internal_attach_property(pg, p);

	xmlFree(enabled);

	/*
	 * Walk its child elements, as appropriate.
	 */
	for (cursor = inst->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		if (op == SVCCFG_OP_APPLY) {
			semerr(gettext("Instance \"%s\" may not contain "
			    "elements in profiles.\n"), i->sc_name,
			    cursor->name);
			return (-1);
		}

		switch (lxml_xlate_element(cursor->name)) {
		case SC_RESTARTER:
			(void) lxml_get_restarter(i, cursor);
			break;
		case SC_DEPENDENCY:
			(void) lxml_get_dependency(i, cursor);
			break;
		case SC_DEPENDENT:
			(void) lxml_get_dependent(i, cursor);
			break;
		case SC_METHOD_CONTEXT:
			(void) lxml_get_entity_method_context(i, cursor);
			break;
		case SC_EXEC_METHOD:
			(void) lxml_get_exec_method(i, cursor);
			break;
		case SC_PROPERTY_GROUP:
			(void) lxml_get_pgroup(i, cursor);
			break;
		case SC_TEMPLATE:
			(void) lxml_get_template(i, cursor);
			break;
		default:
			uu_die(gettext(
			    "illegal element \"%s\" on instance \"%s\"\n"),
			    cursor->name, i->sc_name);
			break;
		}
	}

	return (0);
}

/* ARGSUSED1 */
static int
lxml_get_single_instance(entity_t *entity, xmlNodePtr si)
{
	pgroup_t *pg;
	property_t *p;
	int r;

	pg = internal_pgroup_find_or_create(entity, (char *)scf_pg_general,
	    (char *)scf_group_framework);

	p = internal_property_create(SCF_PROPERTY_SINGLE_INSTANCE,
	    SCF_TYPE_BOOLEAN, 1, (uint64_t)1);

	r = internal_attach_property(pg, p);
	if (r != 0) {
		internal_property_free(p);
		return (-1);
	}

	return (0);
}

/*
 * Translate a service element into an internal instance/property tree, added
 * to bundle.  If op is SVCCFG_OP_APPLY, allow only instance subelements.
 */
static int
lxml_get_service(bundle_t *bundle, xmlNodePtr svc, svccfg_op_t op)
{
	entity_t *s;
	xmlNodePtr cursor;
	xmlChar *type;
	xmlChar *version;
	int e;

	/*
	 * Fetch attributes, as appropriate.
	 */
	s = internal_service_new((char *)xmlGetProp(svc,
	    (xmlChar *)name_attr));

	version = xmlGetProp(svc, (xmlChar *)"version");
	s->sc_u.sc_service.sc_service_version = atol((const char *)version);
	xmlFree(version);

	type = xmlGetProp(svc, (xmlChar *)type_attr);
	s->sc_u.sc_service.sc_service_type = lxml_xlate_service_type(type);
	xmlFree(type);

	/*
	 * Walk its child elements, as appropriate.
	 */
	for (cursor = svc->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		e = lxml_xlate_element(cursor->name);

		if (op == SVCCFG_OP_APPLY && e != SC_INSTANCE) {
			semerr(gettext("Service \"%s\" may not contain the "
			    "non-instance element \"%s\" in a profile.\n"),
			    s->sc_name, cursor->name);

			return (-1);
		}

		switch (e) {
		case SC_INSTANCE:
			(void) lxml_get_instance(s, cursor, op);
			break;
		case SC_TEMPLATE:
			(void) lxml_get_template(s, cursor);
			break;
		case SC_STABILITY:
			(void) lxml_get_entity_stability(s, cursor);
			break;
		case SC_DEPENDENCY:
			(void) lxml_get_dependency(s, cursor);
			break;
		case SC_DEPENDENT:
			(void) lxml_get_dependent(s, cursor);
			break;
		case SC_RESTARTER:
			(void) lxml_get_restarter(s, cursor);
			break;
		case SC_EXEC_METHOD:
			(void) lxml_get_exec_method(s, cursor);
			break;
		case SC_METHOD_CONTEXT:
			(void) lxml_get_entity_method_context(s, cursor);
			break;
		case SC_PROPERTY_GROUP:
			(void) lxml_get_pgroup(s, cursor);
			break;
		case SC_INSTANCE_CREATE_DEFAULT:
			(void) lxml_get_default_instance(s, cursor);
			break;
		case SC_INSTANCE_SINGLE:
			(void) lxml_get_single_instance(s, cursor);
			break;
		default:
			uu_die(gettext(
			    "illegal element \"%s\" on service \"%s\"\n"),
			    cursor->name, s->sc_name);
			break;
		}
	}

	return (internal_attach_service(bundle, s));
}

#ifdef DEBUG
void
lxml_dump(int g, xmlNodePtr p)
{
	if (p && p->name) {
		printf("%d %s\n", g, p->name);

		for (p = p->xmlChildrenNode; p != NULL; p = p->next)
			lxml_dump(g + 1, p);
	}
}
#endif /* DEBUG */

static int
lxml_is_known_dtd(const xmlChar *dtdname)
{
	if (dtdname == NULL ||
	    strcmp(MANIFEST_DTD_PATH, (const char *)dtdname) != 0)
		return (0);

	return (1);
}

static int
lxml_get_bundle(bundle_t *bundle, bundle_type_t bundle_type,
    xmlNodePtr subbundle, svccfg_op_t op)
{
	xmlNodePtr cursor;
	xmlChar *type;
	int e;

	/*
	 * 1.  Get bundle attributes.
	 */
	type = xmlGetProp(subbundle, (xmlChar *)"type");
	bundle->sc_bundle_type = lxml_xlate_bundle_type(type);
	if (bundle->sc_bundle_type != bundle_type &&
	    bundle_type != SVCCFG_UNKNOWN_BUNDLE) {
		semerr(gettext("included bundle of different type.\n"));
		return (-1);
	}

	xmlFree(type);

	switch (op) {
	case SVCCFG_OP_IMPORT:
		if (bundle->sc_bundle_type != SVCCFG_MANIFEST) {
			semerr(gettext("document is not a manifest.\n"));
			return (-1);
		}
		break;
	case SVCCFG_OP_APPLY:
		if (bundle->sc_bundle_type != SVCCFG_PROFILE) {
			semerr(gettext("document is not a profile.\n"));
			return (-1);
		}
		break;
	case SVCCFG_OP_RESTORE:
		if (bundle->sc_bundle_type != SVCCFG_ARCHIVE) {
			semerr(gettext("document is not an archive.\n"));
			return (-1);
		}
		break;
	}

	if ((bundle->sc_bundle_name = xmlGetProp(subbundle,
	    (xmlChar *)"name")) == NULL) {
		semerr(gettext("service bundle lacks name attribute\n"));
		return (-1);
	}

	/*
	 * 2.  Get services, descend into each one and build state.
	 */
	for (cursor = subbundle->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		e = lxml_xlate_element(cursor->name);

		switch (e) {
		case SC_XI_INCLUDE:
			continue;

		case SC_SERVICE_BUNDLE:
			if (lxml_get_bundle(bundle, bundle_type, cursor, op))
				return (-1);
			break;
		case SC_SERVICE:
			(void) lxml_get_service(bundle, cursor, op);
			break;
		}
	}

	return (0);
}

/*
 * Load an XML tree from filename and translate it into an internal service
 * tree bundle.  Require that the bundle be of appropriate type for the
 * operation: archive for RESTORE, manifest for IMPORT, profile for APPLY.
 */
int
lxml_get_bundle_file(bundle_t *bundle, const char *filename, svccfg_op_t op)
{
	xmlDocPtr document;
	xmlNodePtr cursor;
	xmlDtdPtr dtd = NULL;
	xmlValidCtxtPtr vcp;
	boolean_t do_validate;
	char *dtdpath = NULL;
	int r;

	/*
	 * Verify we can read the file before we try to parse it.
	 */
	if (access(filename, R_OK | F_OK) == -1) {
		semerr(gettext("unable to open file: %s\n"), strerror(errno));
		return (-1);
	}

	/*
	 * Until libxml2 addresses DTD-based validation with XInclude, we don't
	 * validate service profiles (i.e. the apply path).
	 */
	do_validate = (op != SVCCFG_OP_APPLY) &&
	    (getenv("SVCCFG_NOVALIDATE") == NULL);
	if (do_validate)
		dtdpath = getenv("SVCCFG_DTD");

	if (dtdpath != NULL)
		xmlLoadExtDtdDefaultValue = 0;

	if ((document = xmlReadFile(filename, NULL, 0)) == NULL) {
		semerr(gettext("couldn't parse document\n"));
		return (-1);
	}

	/*
	 * Verify that this is a document type we understand.
	 */
	if ((dtd = xmlGetIntSubset(document)) == NULL) {
		semerr(gettext("document has no DTD\n"));
		return (-1);
	}

	if (!lxml_is_known_dtd(dtd->SystemID)) {
		semerr(gettext("document DTD unknown; not service bundle?\n"));
		return (-1);
	}

	if ((cursor = xmlDocGetRootElement(document)) == NULL) {
		semerr(gettext("document is empty\n"));
		xmlFreeDoc(document);
		return (-1);
	}

	if (xmlStrcmp(cursor->name, (const xmlChar *)"service_bundle") != 0) {
		semerr(gettext("document is not a service bundle\n"));
		xmlFreeDoc(document);
		return (-1);
	}


	if (dtdpath != NULL) {
		dtd = xmlParseDTD(NULL, (xmlChar *)dtdpath);
		if (dtd == NULL) {
			semerr(gettext("Could not parse DTD \"%s\".\n"),
			    dtdpath);
			return (-1);
		}

		if (document->extSubset != NULL)
			xmlFreeDtd(document->extSubset);

		document->extSubset = dtd;
	}

	if (xmlXIncludeProcessFlags(document, XML_PARSE_XINCLUDE) == -1) {
		semerr(gettext("couldn't handle XInclude statements "
		    "in document\n"));
		return (-1);
	}

	if (do_validate) {
		vcp = xmlNewValidCtxt();
		if (vcp == NULL)
			uu_die(gettext("could not allocate memory"));
		vcp->warning = xmlParserValidityWarning;
		vcp->error = xmlParserValidityError;

		r = xmlValidateDocument(vcp, document);

		xmlFreeValidCtxt(vcp);

		if (r == 0) {
			semerr(gettext("Document is not valid.\n"));
			xmlFreeDoc(document);
			return (-1);
		}
	}


#ifdef DEBUG
	lxml_dump(0, cursor);
#endif /* DEBUG */

	r = lxml_get_bundle(bundle, SVCCFG_UNKNOWN_BUNDLE, cursor, op);

	xmlFreeDoc(document);

	return (r);
}

int
lxml_inventory(const char *filename)
{
	bundle_t *b;
	uu_list_walk_t *svcs, *insts;
	entity_t *svc, *inst;

	b = internal_bundle_new();

	if (lxml_get_bundle_file(b, filename, SVCCFG_OP_IMPORT) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	svcs = uu_list_walk_start(b->sc_bundle_services, 0);
	if (svcs == NULL)
		uu_die(gettext("Couldn't walk services"));

	while ((svc = uu_list_walk_next(svcs)) != NULL) {
		uu_list_t *inst_list;

		inst_list = svc->sc_u.sc_service.sc_service_instances;
		insts = uu_list_walk_start(inst_list, 0);
		if (insts == NULL)
			uu_die(gettext("Couldn't walk instances"));

		while ((inst = uu_list_walk_next(insts)) != NULL)
			(void) printf("svc:/%s:%s\n", svc->sc_name,
			    inst->sc_name);

		uu_list_walk_end(insts);
	}

	uu_list_walk_end(svcs);

	svcs = uu_list_walk_start(b->sc_bundle_services, 0);
	while ((svc = uu_list_walk_next(svcs)) != NULL) {
		(void) fputs("svc:/", stdout);
		(void) puts(svc->sc_name);
	}
	uu_list_walk_end(svcs);

	internal_bundle_free(b);

	return (0);
}
