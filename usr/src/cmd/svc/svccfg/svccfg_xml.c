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
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */


/*
 * XML document manipulation routines
 *
 * These routines provide translation to and from the internal representation to
 * XML.  Directionally-oriented verbs are with respect to the external source,
 * so lxml_get_service() fetches a service from the XML file into the
 * internal representation.
 */

#include <libxml/parser.h>
#include <libxml/xinclude.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <sasl/saslutil.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/param.h>
#include "manifest_hash.h"

#include "svccfg.h"
#include "notify_params.h"

/*
 * snprintf(3C) format strings for constructing property names that include
 * the locale designation.  Use %s to indicate where the locale should go.
 *
 * The VALUE_* symbols are an exception.  The firs %s will be replaced with
 * "value_".  The second %s will be replaced by the name of the value and
 * %%s will be replaced by the locale designation.  These formats are
 * processed twice by snprintf(3C).  The first time captures the value name
 * and the second time captures the locale.
 */
#define	LOCALE_ONLY_FMT		("%s")
#define	COMMON_NAME_FMT		("common_name_%s")
#define	DESCRIPTION_FMT		("description_%s")
#define	UNITS_FMT		("units_%s")
#define	VALUE_COMMON_NAME_FMT	("%s%s_common_name_%%s")
#define	VALUE_DESCRIPTION_FMT	("%s%s_description_%%s")

/* Attribute names */
const char * const delete_attr = "delete";
const char * const enabled_attr = "enabled";
const char * const lang_attr = "lang";
const char * const manpath_attr = "manpath";
const char * const max_attr = "max";
const char * const min_attr = "min";
const char * const name_attr = "name";
const char * const override_attr = "override";
const char * const required_attr = "required";
const char * const section_attr = "section";
const char * const set_attr = "set";
const char * const target_attr = "target";
const char * const timeout_seconds_attr = "timeout_seconds";
const char * const title_attr = "title";
const char * const type_attr = "type";
const char * const uri_attr = "uri";
const char * const value_attr = "value";
const char * const version_attr = "version";
const char * const xml_lang_attr = "xml:lang";
const char * const active_attr = "active";

/* Attribute values */
const char * const all_value = "all";

const char * const true = "true";
const char * const false = "false";

/*
 * The following list must be kept in the same order as that of
 * element_t array
 */
static const char *lxml_elements[] = {
	"astring_list",			/* SC_ASTRING */
	"boolean_list",			/* SC_BOOLEAN */
	"cardinality",			/* SC_CARDINALITY */
	"choices",			/* SC_CHOICES */
	"common_name",			/* SC_COMMON_NAME */
	"constraints",			/* SC_CONSTRAINTS */
	"count_list",			/* SC_COUNT */
	"create_default_instance",	/* SC_INSTANCE_CREATE_DEFAULT */
	"dependency",			/* SC_DEPENDENCY */
	"dependent",			/* SC_DEPENDENT */
	"description",			/* SC_DESCRIPTION */
	"doc_link",			/* SC_DOC_LINK */
	"documentation",		/* SC_DOCUMENTATION */
	"enabled",			/* SC_ENABLED */
	"event",			/* SC_EVENT */
	"exec_method",			/* SC_EXEC_METHOD */
	"fmri_list",			/* SC_FMRI */
	"host_list",			/* SC_HOST */
	"hostname_list",		/* SC_HOSTNAME */
	"include_values",		/* SC_INCLUDE_VALUES */
	"instance",			/* SC_INSTANCE */
	"integer_list",			/* SC_INTEGER */
	"internal_separators",		/* SC_INTERNAL_SEPARATORS */
	"loctext",			/* SC_LOCTEXT */
	"manpage",			/* SC_MANPAGE */
	"method_context",		/* SC_METHOD_CONTEXT */
	"method_credential",		/* SC_METHOD_CREDENTIAL */
	"method_profile",		/* SC_METHOD_PROFILE */
	"method_environment",		/* SC_METHOD_ENVIRONMENT */
	"envvar",			/* SC_METHOD_ENVVAR */
	"net_address_list",		/* SC_NET_ADDR */
	"net_address_v4_list",		/* SC_NET_ADDR_V4 */
	"net_address_v6_list",		/* SC_NET_ADDR_V6 */
	"notification_parameters",	/* SC_NOTIFICATION_PARAMETERS */
	"opaque_list",			/* SC_OPAQUE */
	"parameter",			/* SC_PARAMETER */
	"paramval",			/* SC_PARAMVAL */
	"pg_pattern",			/* SC_PG_PATTERN */
	"prop_pattern",			/* SC_PROP_PATTERN */
	"property",			/* SC_PROPERTY */
	"property_group",		/* SC_PROPERTY_GROUP */
	"propval",			/* SC_PROPVAL */
	"range",			/* SC_RANGE */
	"restarter",			/* SC_RESTARTER */
	"service",			/* SC_SERVICE */
	"service_bundle",		/* SC_SERVICE_BUNDLE */
	"service_fmri",			/* SC_SERVICE_FMRI */
	"single_instance",		/* SC_INSTANCE_SINGLE */
	"stability",			/* SC_STABILITY */
	"template",			/* SC_TEMPLATE */
	"time_list",			/* SC_TIME */
	"type",				/* SC_TYPE */
	"units",			/* SC_UNITS */
	"uri_list",			/* SC_URI */
	"ustring_list",			/* SC_USTRING */
	"value",			/* SC_VALUE */
	"value_node",			/* SC_VALUE_NODE */
	"values",			/* SC_VALUES */
	"visibility",			/* SC_VISIBILITY */
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
	"",				/* SC_CARDINALITY */
	"",				/* SC_CHOICES */
	"",				/* SC_COMMON_NAME */
	"",				/* SC_CONSTRAINTS */
	"count",			/* SC_COUNT */
	"",				/* SC_INSTANCE_CREATE_DEFAULT */
	"",				/* SC_DEPENDENCY */
	"",				/* SC_DEPENDENT */
	"",				/* SC_DESCRIPTION */
	"",				/* SC_DOC_LINK */
	"",				/* SC_DOCUMENTATION */
	"",				/* SC_ENABLED */
	"",				/* SC_EVENT */
	"",				/* SC_EXEC_METHOD */
	"fmri",				/* SC_FMRI */
	"host",				/* SC_HOST */
	"hostname",			/* SC_HOSTNAME */
	"",				/* SC_INCLUDE_VALUES */
	"",				/* SC_INSTANCE */
	"integer",			/* SC_INTEGER */
	"",				/* SC_INTERNAL_SEPARATORS */
	"",				/* SC_LOCTEXT */
	"",				/* SC_MANPAGE */
	"",				/* SC_METHOD_CONTEXT */
	"",				/* SC_METHOD_CREDENTIAL */
	"",				/* SC_METHOD_PROFILE */
	"",				/* SC_METHOD_ENVIRONMENT */
	"",				/* SC_METHOD_ENVVAR */
	"net_address",			/* SC_NET_ADDR */
	"net_address_v4",		/* SC_NET_ADDR_V4 */
	"net_address_v6",		/* SC_NET_ADDR_V6 */
	"",				/* SC_NOTIFICATION_PARAMETERS */
	"opaque",			/* SC_OPAQUE */
	"",				/* SC_PARAMETER */
	"",				/* SC_PARAMVAL */
	"",				/* SC_PG_PATTERN */
	"",				/* SC_PROP_PATTERN */
	"",				/* SC_PROPERTY */
	"",				/* SC_PROPERTY_GROUP */
	"",				/* SC_PROPVAL */
	"",				/* SC_RANGE */
	"",				/* SC_RESTARTER */
	"",				/* SC_SERVICE */
	"",				/* SC_SERVICE_BUNDLE */
	"",				/* SC_SERVICE_FMRI */
	"",				/* SC_INSTANCE_SINGLE */
	"",				/* SC_STABILITY */
	"",				/* SC_TEMPLATE */
	"time",				/* SC_TIME */
	"",				/* SC_TYPE */
	"",				/* SC_UNITS */
	"uri",				/* SC_URI */
	"ustring",			/* SC_USTRING */
	"",				/* SC_VALUE */
	"",				/* SC_VALUE_NODE */
	"",				/* SC_VALUES */
	"",				/* SC_VISIBILITY */
	"",				/* SC_XI_FALLBACK */
	""				/* SC_XI_INCLUDE */
};

int
lxml_init()
{
	if (getenv("SVCCFG_NOVALIDATE") == NULL) {
		/*
		 * DTD validation, with line numbers.
		 */
		(void) xmlLineNumbersDefault(1);
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
	case SC_NET_ADDR:	return (SCF_TYPE_NET_ADDR);
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

static element_t
lxml_type_to_element(scf_type_t type)
{
	switch (type) {
	case SCF_TYPE_ASTRING:		return (SC_ASTRING);
	case SCF_TYPE_BOOLEAN:		return (SC_BOOLEAN);
	case SCF_TYPE_COUNT:		return (SC_COUNT);
	case SCF_TYPE_FMRI:		return (SC_FMRI);
	case SCF_TYPE_HOST:		return (SC_HOST);
	case SCF_TYPE_HOSTNAME:		return (SC_HOSTNAME);
	case SCF_TYPE_INTEGER:		return (SC_INTEGER);
	case SCF_TYPE_NET_ADDR:		return (SC_NET_ADDR);
	case SCF_TYPE_NET_ADDR_V4:	return (SC_NET_ADDR_V4);
	case SCF_TYPE_NET_ADDR_V6:	return (SC_NET_ADDR_V6);
	case SCF_TYPE_OPAQUE:		return (SC_OPAQUE);
	case SCF_TYPE_TIME:		return (SC_TIME);
	case SCF_TYPE_URI:		return (SC_URI);
	case SCF_TYPE_USTRING:		return (SC_USTRING);

	default:
		uu_die(gettext("unknown value type (%d)\n"), type);
	}

	/* NOTREACHED */
}

/*
 * Create a SCF_TYPE_BOOLEAN property name pname and attach it to the
 * property group at pgrp.  The value of the property will be set from the
 * attribute named attr.  attr must have a value of 0, 1, true or false.
 *
 * Zero is returned on success.  An error is indicated by -1.  It indicates
 * that either the attribute had an invalid value or that we could not
 * attach the property to pgrp.  The attribute should not have an invalid
 * value if the DTD is correctly written.
 */
static int
new_bool_prop_from_attr(pgroup_t *pgrp, const char *pname, xmlNodePtr n,
    const char *attr)
{
	uint64_t bool;
	xmlChar *val;
	property_t *p;
	int r;

	val = xmlGetProp(n, (xmlChar *)attr);
	if (val == NULL)
		return (0);

	if ((xmlStrcmp(val, (xmlChar *)"0") == 0) ||
	    (xmlStrcmp(val, (xmlChar *)"false") == 0)) {
		bool = 0;
	} else if ((xmlStrcmp(val, (xmlChar *)"1") == 0) ||
	    (xmlStrcmp(val, (xmlChar *)"true") == 0)) {
		bool = 1;
	} else {
		xmlFree(val);
		return (-1);
	}
	xmlFree(val);
	p = internal_property_create(pname, SCF_TYPE_BOOLEAN, 1, bool);
	r = internal_attach_property(pgrp, p);

	if (r != 0)
		internal_property_free(p);

	return (r);
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
new_opt_str_prop_from_attr(pgroup_t *pgrp, const char *pname, scf_type_t ty,
    xmlNodePtr n, const char *attr, const char *dflt)
{
	xmlChar *val;
	property_t *p;
	int r;

	val = xmlGetProp(n, (xmlChar *)attr);
	if (val == NULL) {
		if (dflt == NULL) {
			/*
			 * A missing attribute is considered to be a
			 * success in this function, because many of the
			 * attributes are optional.  Missing non-optional
			 * attributes will be detected later when template
			 * validation is done.
			 */
			return (0);
		} else {
			val = (xmlChar *)dflt;
		}
	}

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

static void
lxml_validate_element(xmlNodePtr n)
{
	xmlValidCtxtPtr	vcp;

	if (n->doc == NULL)
		uu_die(gettext("Could not validate element\n"));

	if (n->doc->extSubset == NULL) {
		xmlDtdPtr dtd;
		dtd = xmlParseDTD(NULL, n->doc->intSubset->SystemID);

		if (dtd == NULL) {
			uu_die(gettext("Could not parse DTD \"%s\".\n"),
			    n->doc->intSubset->SystemID);
		}

		n->doc->extSubset = dtd;
	}

	vcp = xmlNewValidCtxt();
	if (vcp == NULL)
		uu_die(gettext("could not allocate memory"));

	vcp->warning = xmlParserValidityWarning;
	vcp->error = xmlParserValidityError;

	if (xmlValidateElement(vcp, n->doc, n) == 0)
		uu_die(gettext("Document is not valid.\n"));

	xmlFreeValidCtxt(vcp);
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

/*
 * Take a value_t structure and a type and value.  Based on the type
 * ensure that the value is of that type.  If so store the value in
 * the correct location of the value_t structure.
 *
 * If the value is NULL, the value_t structure will have been created
 * and the value would have ultimately been stored as a string value
 * but at the time the type was unknown.  Now the type should be known
 * so take the type and value from value_t and validate and store
 * the value correctly if the value is of the stated type.
 */
void
lxml_store_value(value_t *v, element_t type, const xmlChar *value)
{
	char *endptr;
	int fov = 0;
	scf_type_t scf_type = SCF_TYPE_INVALID;

	if (value == NULL) {
		type = lxml_type_to_element(v->sc_type);
		value = (const xmlChar *)v->sc_u.sc_string;
		fov = 1;
	}

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
	case SC_NET_ADDR:
	case SC_NET_ADDR_V4:
	case SC_NET_ADDR_V6:
	case SC_FMRI:
	case SC_URI:
	case SC_TIME:
	case SC_ASTRING:
	case SC_USTRING:
		scf_type = lxml_element_to_type(type);

		v->sc_u.sc_string = safe_strdup((const char *)value);
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

	/* Free the old value */
	if (fov && v->sc_free != NULL)
		free((char *)value);
}

static value_t *
lxml_make_value(element_t type, const xmlChar *value)
{
	value_t *v;

	v = internal_value_new();

	v->sc_type = lxml_element_to_type(type);

	lxml_store_value(v, type, value);

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
	int op = pgrp->sc_parent->sc_op;

	p = internal_property_new();

	p->sc_property_name = (char *)xmlGetProp(propval, (xmlChar *)name_attr);
	if ((p->sc_property_name == NULL) || (*p->sc_property_name == 0))
		uu_die(gettext("property name missing in group '%s'\n"),
		    pgrp->sc_pgroup_name);

	type = xmlGetProp(propval, (xmlChar *)type_attr);
	if ((type != NULL) && (*type != 0)) {
		for (r = 0;
		    r < sizeof (lxml_prop_types) / sizeof (char *); ++r) {
			if (xmlStrcmp(type,
			    (const xmlChar *)lxml_prop_types[r]) == 0)
				break;
		}

		if (r >= sizeof (lxml_prop_types) / sizeof (char *))
			uu_die(gettext("property type invalid for "
			    "property '%s/%s'\n"), pgrp->sc_pgroup_name,
			    p->sc_property_name);

		p->sc_value_type = lxml_element_to_type(r);
	} else if (op == SVCCFG_OP_APPLY) {
		/*
		 * Store the property type as invalid, and the value
		 * as an ASTRING and let the bundle apply code validate
		 * the type/value once the type is found.
		 */
		est->sc_miss_type = B_TRUE;
		p->sc_value_type = SCF_TYPE_INVALID;
		r = SC_ASTRING;
	} else {
		uu_die(gettext("property type missing for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);
	}

	val = xmlGetProp(propval, (xmlChar *)value_attr);
	if (val == NULL)
		uu_die(gettext("property value missing for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, p->sc_property_name);

	v = lxml_make_value(r, val);
	xmlFree(val);
	internal_attach_value(p, v);

	xmlFree(type);

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
	int op = pgrp->sc_parent->sc_op;

	p = internal_property_new();

	if (((p->sc_property_name = (char *)xmlGetProp(property,
	    (xmlChar *)name_attr)) == NULL) || (*p->sc_property_name == 0))
		uu_die(gettext("property name missing in group \'%s\'\n"),
		    pgrp->sc_pgroup_name);

	type = xmlGetProp(property, (xmlChar *)type_attr);
	if ((type != NULL) && (*type != 0)) {
		for (r = 0;
		    r < sizeof (lxml_prop_types) / sizeof (char *); r++) {
			if (xmlStrcmp(type,
			    (const xmlChar *)lxml_prop_types[r]) == 0)
				break;
		}

		if (r >= sizeof (lxml_prop_types) / sizeof (char *))
			uu_die(gettext("property type invalid for "
			    "property '%s/%s'\n"), pgrp->sc_pgroup_name,
			    p->sc_property_name);

		p->sc_value_type = lxml_element_to_type(r);
	} else if (op == SVCCFG_OP_APPLY) {
		/*
		 * Store the property type as invalid, and let the bundle apply
		 * code validate the type/value once the type is found.
		 */
		p->sc_value_type = SCF_TYPE_INVALID;
		est->sc_miss_type = B_TRUE;
	} else {
		uu_die(gettext("property type missing for "
		    "property \'%s/%s\'\n"), pgrp->sc_pgroup_name,
		    p->sc_property_name);
	}

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
		case SC_NET_ADDR:
		case SC_NET_ADDR_V4:
		case SC_NET_ADDR_V6:
		case SC_OPAQUE:
		case SC_TIME:
		case SC_URI:
		case SC_USTRING:
			/*
			 * If the type is invalid then this is an apply
			 * operation and the type can be taken from the
			 * value list.
			 */
			if (p->sc_value_type == SCF_TYPE_INVALID) {
				p->sc_value_type = lxml_element_to_type(r);
				type = xmlStrdup((const
				    xmlChar *)lxml_prop_types[r]);

			} else if (strcmp(lxml_prop_types[r],
			    (const char *)type) != 0) {
				uu_die(gettext("property \'%s\' "
				    "type-to-list mismatch\n"),
				    p->sc_property_name);
			}

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
	if (pgrp->sc_parent->sc_op == SVCCFG_OP_APPLY)
		lxml_validate_element(stab);

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

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_USER, SCF_TYPE_ASTRING,
	    cred, "user", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_GROUP, SCF_TYPE_ASTRING,
	    cred, "group", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_SUPP_GROUPS,
	    SCF_TYPE_ASTRING, cred, "supp_groups", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_PRIVILEGES,
	    SCF_TYPE_ASTRING, cred, "privileges", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_LIMIT_PRIVILEGES,
	    SCF_TYPE_ASTRING, cred, "limit_privileges", NULL) != 0)
		return (-1);

	return (0);
}

static char *
lxml_get_envvar(xmlNodePtr envvar)
{
	char *name;
	char *value;
	char *ret;

	name = (char *)xmlGetProp(envvar, (xmlChar *)name_attr);
	value = (char *)xmlGetProp(envvar, (xmlChar *)value_attr);

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

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_WORKING_DIRECTORY,
	    SCF_TYPE_ASTRING, ctx, "working_directory", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_PROJECT,
	    SCF_TYPE_ASTRING, ctx, "project", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_RESOURCE_POOL,
	    SCF_TYPE_ASTRING, ctx, "resource_pool", NULL) != 0)
		return (-1);

	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_SECFLAGS,
	    SCF_TYPE_ASTRING, ctx, "security_flags", NULL) != 0)
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

	if (entity->sc_op == SVCCFG_OP_APPLY)
		lxml_validate_element(emeth);

	name = xmlGetProp(emeth, (xmlChar *)name_attr);
	pg = internal_pgroup_find_or_create(entity, (char *)name,
	    (char *)SCF_GROUP_METHOD);
	xmlFree(name);

	if (new_str_prop_from_attr(pg, SCF_PROPERTY_TYPE, SCF_TYPE_ASTRING,
	    emeth, type_attr) != 0 ||
	    new_str_prop_from_attr(pg, SCF_PROPERTY_EXEC, SCF_TYPE_ASTRING,
	    emeth, "exec") != 0)
		return (-1);

	timeout = xmlGetProp(emeth, (xmlChar *)timeout_seconds_attr);
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
	 * working_directory, profile, user, group, privileges,
	 * limit_privileges, security_flags
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

	if (entity->sc_op == SVCCFG_OP_APPLY)
		lxml_validate_element(dependency);

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

	if (entity->sc_op == SVCCFG_OP_APPLY)
		lxml_validate_element(dependent);

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

	if (((stabval = xmlGetProp(rstr, (xmlChar *)value_attr)) == NULL) ||
	    (*stabval == 0)) {
		uu_warn(gettext("no stability value found\n"));
		stabval = (xmlChar *)safe_strdup("External");
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
lxml_get_paramval(pgroup_t *pgrp, const char *propname, xmlNodePtr pval)
{
	property_t *p;
	char *value;
	char *prop;

	prop = safe_strdup(propname);

	value = (char *)xmlGetProp(pval, (xmlChar *)value_attr);
	if (value == NULL || *value == '\0')
		uu_die(gettext("property value missing for property '%s/%s'\n"),
		    pgrp->sc_pgroup_name, propname);
	p = internal_property_create(prop, SCF_TYPE_ASTRING, 1, value);

	(void) internal_attach_property(pgrp, p);
}

static void
lxml_get_parameter(pgroup_t *pgrp, const char *propname, xmlNodePtr param)
{
	property_t *p = internal_property_new();

	p->sc_property_name = safe_strdup(propname);
	p->sc_value_type = SCF_TYPE_ASTRING;

	(void) lxml_get_value(p, SC_ASTRING, param);

	(void) internal_attach_property(pgrp, p);
}

static void
lxml_get_type(pgroup_t *pgrp, xmlNodePtr type)
{
	property_t *p;
	xmlChar *name;
	xmlChar *active;
	xmlNodePtr cursor;
	uint64_t active_val;
	size_t sz = max_scf_name_len + 1;
	char *propname = safe_malloc(sz);

	if (pgrp->sc_parent->sc_op == SVCCFG_OP_APPLY)
		lxml_validate_element(type);

	name = xmlGetProp(type, (xmlChar *)name_attr);
	if (name == NULL || *name == '\0')
		uu_die(gettext("attribute name missing in element 'type'\n"));

	for (cursor = type->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		xmlChar *pname;

		if (lxml_ignorable_block(cursor))
			continue;

		pname = xmlGetProp(cursor, (xmlChar *)name_attr);
		if (pname == NULL || *pname == '\0')
			uu_die(gettext(
			    "attribute name missing in sub-element of type\n"));

		if (snprintf(propname, sz, "%s,%s", (char *)name,
		    (char *)pname) >= sz)
			uu_die(gettext("name '%s,%s' is too long\n"),
			    (char *)name, (char *)pname);
		xmlFree(pname);

		switch (lxml_xlate_element(cursor->name)) {
		case SC_PARAMETER:
			lxml_get_parameter(pgrp, propname, cursor);
			break;

		case SC_PARAMVAL:
			lxml_get_paramval(pgrp, propname, cursor);
			break;

		default:
			uu_die(gettext("unknown element %s\n"), cursor->name);
		}
	}

	active = xmlGetProp(type, (xmlChar *)active_attr);
	if (active == NULL || strcmp(true, (const char *)active) == 0)
		active_val = 1;
	else
		active_val = 0;
	xmlFree(active);

	if (snprintf(propname, sz, "%s,%s", (char *)name,
	    SCF_PROPERTY_ACTIVE_POSTFIX) >= sz)
		uu_die(gettext("name '%s,%s' is too long\n"),
		    (char *)name, SCF_PROPERTY_ACTIVE_POSTFIX);

	p = internal_property_create(propname, SCF_TYPE_BOOLEAN, 1, active_val);

	(void) internal_attach_property(pgrp, p);

	xmlFree(name);
}

static void
lxml_get_event(entity_t *entity, const char *pgname, xmlNodePtr np)
{
	xmlNodePtr cursor;
	pgroup_t *pgrp;

	pgrp = internal_pgroup_find_or_create(entity, pgname,
	    SCF_NOTIFY_PARAMS_PG_TYPE);
	for (cursor = np->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_EVENT:
			continue;

		case SC_TYPE:
			lxml_get_type(pgrp, cursor);
			break;

		default:
			uu_warn(gettext("illegal element '%s' on "
			    "notification parameters\n"), cursor->name);
		}
	}
}

static int
lxml_get_notification_parameters(entity_t *entity, xmlNodePtr np)
{
	char *event = NULL;
	char **pgs = NULL;
	char **p;
	char *pgname = NULL;
	xmlNodePtr cursor;
	int32_t tset, t;
	size_t sz = max_scf_name_len + 1;
	int count;
	int r = -1;

	for (count = 0, cursor = np->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		if (lxml_xlate_element(cursor->name) == SC_EVENT) {
			xmlChar *s;

			count++;
			if (count > 1)
				uu_die(gettext("Can't have more than 1 element "
				    "event in a notification parameter\n"));
			s = xmlGetProp(cursor, (xmlChar *)value_attr);
			if (s == NULL || (event = strdup((char *)s)) == NULL)
				uu_die(gettext("couldn't allocate memory"));
			xmlFree(s);
		}
	}

	pgs = tokenize(event, ",");

	switch (tset = check_tokens(pgs)) {
	case INVALID_TOKENS:
		uu_die(gettext("Invalid input.\n"));
		/*NOTREACHED*/
	case MIXED_TOKENS:
		semerr(gettext("Can't mix SMF and FMA event definitions\n"));
		goto out;
	case FMA_TOKENS:
		/* make sure this is SCF_NOTIFY_PARAMS_INST */
		if (entity->sc_etype != SVCCFG_INSTANCE_OBJECT ||
		    strcmp(entity->sc_fmri, SCF_NOTIFY_PARAMS_INST) != 0) {
			semerr(gettext(
			    "Non-SMF transition events must go to %s\n"),
			    SCF_NOTIFY_PARAMS_INST);
			goto out;
		}
		pgname = safe_malloc(sz);
		for (p = pgs; *p; ++p) {
			if (snprintf(pgname, sz, "%s,%s", de_tag(*p),
			    SCF_NOTIFY_PG_POSTFIX) >= sz)
				uu_die(gettext("event name too long: %s\n"),
				    *p);

			lxml_get_event(entity, pgname, np);
		}
		break;

	default:	/* smf state transition tokens */
		if (entity->sc_etype == SVCCFG_SERVICE_OBJECT &&
		    strcmp(entity->sc_fmri, SCF_SERVICE_GLOBAL) == 0) {
			semerr(gettext(
			    "Can't set events for global service\n"));
			goto out;
		}
		for (t = 0x1; t < SCF_STATE_ALL; t <<= 1) {
			if (t & tset) {
				lxml_get_event(entity, tset_to_string(t), np);
			}
			if ((t << 16) & tset) {
				lxml_get_event(entity, tset_to_string(t << 16),
				    np);
			}
		}
	}

	r = 0;
out:
	free(pgname);
	free(pgs);
	free(event);

	return (r);
}

/*
 * Add a property containing the localized text from the manifest.  The
 * property is added to the property group at pg.  The name of the created
 * property is based on the format at pn_format.  This is an snprintf(3C)
 * format containing a single %s conversion specification.  At conversion
 * time, the %s is replaced by the locale designation.
 *
 * source is the source element and it is only used for error messages.
 */
static int
lxml_get_loctext(entity_t *service, pgroup_t *pg, xmlNodePtr loctext,
    const char *pn_format, const char *source)
{
	int extra;
	xmlNodePtr cursor;
	xmlChar *val;
	char *stripped, *cp;
	property_t *p;
	char *prop_name;
	int r;

	if (((val = xmlGetProp(loctext, (xmlChar *)xml_lang_attr)) == NULL) ||
	    (*val == 0)) {
		if (((val = xmlGetProp(loctext,
		    (xmlChar *)lang_attr)) == NULL) || (*val == 0)) {
			val = (xmlChar *)"unknown";
		}
	}

	_scf_sanitize_locale((char *)val);
	prop_name = safe_malloc(max_scf_name_len + 1);
	if ((extra = snprintf(prop_name, max_scf_name_len + 1, pn_format,
	    val)) >= max_scf_name_len + 1) {
		extra -= max_scf_name_len;
		uu_die(gettext("%s attribute is %d characters too long for "
		    "%s in %s\n"),
		    xml_lang_attr, extra, source, service->sc_name);
	}
	xmlFree(val);

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
	stripped = safe_strdup((const char *)cursor->content);

	for (; isspace(*stripped); stripped++)
		;
	for (cp = stripped + strlen(stripped) - 1; isspace(*cp); cp--)
		;
	*(cp + 1) = '\0';

	p = internal_property_create(prop_name, SCF_TYPE_USTRING, 1,
	    stripped);

	r = internal_attach_property(pg, p);
	if (r != 0) {
		internal_property_free(p);
		free(prop_name);
	}

	return (r);
}

/*
 * This function processes all loctext elements in the current XML element
 * designated by container.  A property is created for each loctext element
 * and added to the property group at pg.  The name of the property is
 * derived from the loctext language designation using the format at
 * pn_format.  pn_format should be an snprintf format string containing one
 * %s which is replaced by the language designation.
 *
 * The function returns 0 on success and -1 if it is unable to attach the
 * newly created property to pg.
 */
static int
lxml_get_all_loctext(entity_t *service, pgroup_t *pg, xmlNodePtr container,
    const char *pn_format, const char *source)
{
	xmlNodePtr cursor;

	/*
	 * Iterate through one or more loctext elements.  The locale is
	 * used to generate the property name; the contents are the ustring
	 * value for the property.
	 */
	for (cursor = container->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_LOCTEXT:
			if (lxml_get_loctext(service, pg, cursor, pn_format,
			    source))
				return (-1);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" on %s element "
			    "for \"%s\"\n"), cursor->name, container->name,
			    service->sc_name);
			break;
		}
	}

	return (0);
}

/*
 * Obtain the specified cardinality attribute and place it in a property
 * named prop_name.  The converted attribute is placed at *value, and the
 * newly created property is returned to propp.  NULL is returned to propp
 * if the attribute is not provided in the manifest.
 *
 * 0 is returned upon success, and -1 indicates that the manifest contained
 * an invalid cardinality value.
 */
static int
lxml_get_cardinality_attribute(entity_t *service, xmlNodePtr cursor,
    const char *attr_name, const char *prop_name, uint64_t *value,
    property_t **propp)
{
	char *c;
	property_t *p;
	xmlChar *val;
	uint64_t count;
	char *endptr;

	*propp = NULL;
	val = xmlGetProp(cursor, (xmlChar *)attr_name);
	if (val == NULL)
		return (0);
	if (*val == 0) {
		xmlFree(val);
		return (0);
	}

	/*
	 * Make sure that the string at val doesn't have a leading minus
	 * sign.  The strtoull() call below does not catch this problem.
	 */
	for (c = (char *)val; *c != 0; c++) {
		if (isspace(*c))
			continue;
		if (isdigit(*c))
			break;
		semerr(gettext("\"%c\" is not a legal character in the %s "
		    "attribute of the %s element in %s.\n"), *c,
		    attr_name, prop_name, service->sc_name);
		xmlFree(val);
		return (-1);
	}
	errno = 0;
	count = strtoull((char *)val, &endptr, 10);
	if (errno != 0 || endptr == (char *)val || *endptr) {
		semerr(gettext("\"%s\" is not a legal number for the %s "
		    "attribute of the %s element in %s.\n"), (char *)val,
		    attr_name, prop_name, service->sc_name);
		xmlFree(val);
		return (-1);
	}

	xmlFree(val);

	/* Value is valid.  Create the property. */
	p = internal_property_create(prop_name, SCF_TYPE_COUNT, 1, count);
	*value = count;
	*propp = p;
	return (0);
}

/*
 * The cardinality is specified by two attributes max and min at cursor.
 * Both are optional, but if present they must be unsigned integers.
 */
static int
lxml_get_tm_cardinality(entity_t *service, pgroup_t *pg, xmlNodePtr cursor)
{
	int min_attached = 0;
	int compare = 1;
	property_t *min_prop;
	property_t *max_prop;
	uint64_t max;
	uint64_t min;
	int r;

	r = lxml_get_cardinality_attribute(service, cursor, min_attr,
	    SCF_PROPERTY_TM_CARDINALITY_MIN, &min, &min_prop);
	if (r != 0)
		return (r);
	if (min_prop == NULL)
		compare = 0;
	r = lxml_get_cardinality_attribute(service, cursor, max_attr,
	    SCF_PROPERTY_TM_CARDINALITY_MAX, &max, &max_prop);
	if (r != 0)
		goto errout;
	if ((max_prop != NULL) && (compare == 1)) {
		if (max < min) {
			semerr(gettext("Cardinality max is less than min for "
			    "the %s element in %s.\n"), pg->sc_pgroup_name,
			    service->sc_fmri);
			goto errout;
		}
	}

	/* Attach the properties to the property group. */
	if (min_prop) {
		if (internal_attach_property(pg, min_prop) == 0) {
			min_attached = 1;
		} else {
			goto errout;
		}
	}
	if (max_prop) {
		if (internal_attach_property(pg, max_prop) != 0) {
			if (min_attached)
				internal_detach_property(pg, min_prop);
			goto errout;
		}
	}
	return (0);

errout:
	if (min_prop)
		internal_property_free(min_prop);
	if (max_prop)
		internal_property_free(max_prop);
	return (-1);
}

/*
 * Get the common_name which is present as localized text at common_name in
 * the manifest.  The common_name is stored as the value of a property in
 * the property group whose name is SCF_PG_TM_COMMON_NAME and type is
 * SCF_GROUP_TEMPLATE.  This property group will be created in service if
 * it is not already there.
 */
static int
lxml_get_tm_common_name(entity_t *service, xmlNodePtr common_name)
{
	pgroup_t *pg;

	/*
	 * Create the property group, if absent.
	 */
	pg = internal_pgroup_find_or_create(service, SCF_PG_TM_COMMON_NAME,
	    SCF_GROUP_TEMPLATE);

	return (lxml_get_all_loctext(service, pg, common_name, LOCALE_ONLY_FMT,
	    "common_name"));
}

/*
 * Get the description which is present as localized text at description in
 * the manifest.  The description is stored as the value of a property in
 * the property group whose name is SCF_PG_TM_DESCRIPTION and type is
 * SCF_GROUP_TEMPLATE.  This property group will be created in service if
 * it is not already there.
 */
static int
lxml_get_tm_description(entity_t *service, xmlNodePtr description)
{
	pgroup_t *pg;

	/*
	 * Create the property group, if absent.
	 */
	pg = internal_pgroup_find_or_create(service, SCF_PG_TM_DESCRIPTION,
	    SCF_GROUP_TEMPLATE);

	return (lxml_get_all_loctext(service, pg, description,
	    LOCALE_ONLY_FMT, "description"));
}

static char *
lxml_label_to_groupname(const char *prefix, const char *in)
{
	char *out, *cp;
	size_t len, piece_len;

	out = uu_zalloc(2 * max_scf_name_len + 1);
	if (out == NULL)
		return (NULL);

	(void) strlcpy(out, prefix, 2 * max_scf_name_len + 1);

	len = strlcat(out, in, 2 * max_scf_name_len + 1);
	if (len > max_scf_name_len) {
		/* Use the first half and the second half. */
		piece_len = (max_scf_name_len - 2) / 2;

		(void) strncpy(out + piece_len, "..", 2);

		(void) strcpy(out + piece_len + 2, out + (len - piece_len));
	}

	/*
	 * Translate non-property characters to '_'.
	 */
	for (cp = out; *cp != '\0'; ++cp) {
		if (!(isalnum(*cp) || *cp == '_' || *cp == '-'))
			*cp = '_';
	}

	return (out);
}

/*
 * If *p is NULL, astring_prop_value() first creates a property with the
 * name specified in prop_name.  The address of the newly created property
 * is placed in *p.
 *
 * In either case, newly created property or existing property, a new
 * SCF_TYPE_ASTRING value will created and attached to the property at *p.
 * The value of the newly created property is prop_value.
 *
 * free_flag is used to indicate whether or not the memory at prop_value
 * should be freed when the property is freed by a call to
 * internal_property_free().
 */
static void
astring_prop_value(property_t **p, const char *prop_name, char *prop_value,
    boolean_t free_flag)
{
	value_t *v;

	if (*p == NULL) {
		/* Create the property */
		*p = internal_property_new();
		(*p)->sc_property_name = (char *)prop_name;
		(*p)->sc_value_type = SCF_TYPE_ASTRING;
	}

	/* Add the property value to the property's list of values. */
	v = internal_value_new();
	v->sc_type = SCF_TYPE_ASTRING;
	if (free_flag == B_TRUE)
		v->sc_free = lxml_free_str;
	v->sc_u.sc_string = prop_value;
	internal_attach_value(*p, v);
}

/*
 * If p points to a null pointer, create an internal_separators property
 * saving the address at p.  For each character at seps create a property
 * value and attach it to the property at p.
 */
static void
seps_to_prop_values(property_t **p, xmlChar *seps)
{
	value_t *v;
	char val_str[2];

	if (*p == NULL) {
		*p = internal_property_new();
		(*p)->sc_property_name =
		    (char *)SCF_PROPERTY_INTERNAL_SEPARATORS;
		(*p)->sc_value_type = SCF_TYPE_ASTRING;
	}

	/* Add the values to the property's list. */
	val_str[1] = 0;		/* Terminate the string. */
	for (; *seps != 0; seps++) {
		v = internal_value_new();
		v->sc_type = (*p)->sc_value_type;
		v->sc_free = lxml_free_str;
		val_str[0] = *seps;
		v->sc_u.sc_string = safe_strdup(val_str);
		internal_attach_value(*p, v);
	}
}

/*
 * Create an internal_separators property and attach it to the property
 * group at pg.  The separator characters are provided in the text nodes
 * that are the children of seps.  Each separator character is stored as a
 * property value in the internal_separators property.
 */
static int
lxml_get_tm_internal_seps(entity_t *service, pgroup_t *pg, xmlNodePtr seps)
{
	xmlNodePtr cursor;
	property_t *prop = NULL;
	int r;

	for (cursor = seps->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (strcmp("text", (const char *)cursor->name) == 0) {
			seps_to_prop_values(&prop, cursor->content);
		} else if (strcmp("comment", (const char *)cursor->name) != 0) {
			uu_die(gettext("illegal element \"%s\" on %s element "
			    "for \"%s\"\n"), cursor->name, seps->name,
			    service->sc_name);
		}
	}
	if (prop == NULL) {
		semerr(gettext("The %s element in %s had an empty list of "
		    "separators.\n"), (const char *)seps->name,
		    service->sc_name);
		return (-1);
	}
	r = internal_attach_property(pg, prop);
	if (r != 0)
		internal_property_free(prop);
	return (r);
}

static int
lxml_get_tm_manpage(entity_t *service, xmlNodePtr manpage)
{
	pgroup_t *pg;
	char *pgname;
	char *name;
	xmlChar *title;
	xmlChar *section;

	/*
	 * Fetch title and section attributes, convert to something sanitized,
	 * and create property group.
	 */
	title = xmlGetProp(manpage, (xmlChar *)title_attr);
	if (title == NULL)
		return (-1);
	section = xmlGetProp(manpage, (xmlChar *)section_attr);
	if (section == NULL) {
		xmlFree(title);
		return (-1);
	}

	name = safe_malloc(max_scf_name_len + 1);

	/* Find existing property group with underscore separators */
	(void) snprintf(name, max_scf_name_len + 1, "%s_%s", title, section);
	pgname = lxml_label_to_groupname(SCF_PG_TM_MAN_PREFIX, name);
	pg = internal_pgroup_find(service, pgname, SCF_GROUP_TEMPLATE);

	uu_free(pgname);
	(void) snprintf(name, max_scf_name_len + 1, "%s%s", title, section);
	pgname = lxml_label_to_groupname(SCF_PG_TM_MAN_PREFIX, name);

	if (pg == NULL) {
		pg = internal_pgroup_find_or_create(service, pgname,
		    SCF_GROUP_TEMPLATE);
	} else {
		/* Rename property group */
		free((char *)pg->sc_pgroup_name);
		pg->sc_pgroup_name = safe_strdup(pgname);
	}

	uu_free(pgname);
	free(name);
	xmlFree(section);
	xmlFree(title);


	/*
	 * Each attribute is an astring property within the group.
	 */
	if (new_str_prop_from_attr(pg, SCF_PROPERTY_TM_TITLE,
	    SCF_TYPE_ASTRING, manpage, title_attr) != 0 ||
	    new_str_prop_from_attr(pg, SCF_PROPERTY_TM_SECTION,
	    SCF_TYPE_ASTRING, manpage, section_attr) != 0 ||
	    new_str_prop_from_attr(pg, SCF_PROPERTY_TM_MANPATH,
	    SCF_TYPE_ASTRING, manpage, manpath_attr) != 0)
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
	name = xmlGetProp(doc_link, (xmlChar *)name_attr);
	if (name == NULL)
		return (-1);

	pgname = (char *)lxml_label_to_groupname(SCF_PG_TM_DOC_PREFIX,
	    (const char *)name);

	pg = internal_pgroup_find_or_create(service, pgname,
	    (char *)SCF_GROUP_TEMPLATE);

	uu_free(pgname);
	xmlFree(name);

	/*
	 * Each attribute is an astring property within the group.
	 */
	if (new_str_prop_from_attr(pg, SCF_PROPERTY_TM_NAME, SCF_TYPE_ASTRING,
	    doc_link, name_attr) != 0 ||
	    new_str_prop_from_attr(pg, SCF_PROPERTY_TM_URI, SCF_TYPE_ASTRING,
	    doc_link, uri_attr) != 0)
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
lxml_get_prop_pattern_attributes(pgroup_t *pg, xmlNodePtr cursor)
{
	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_TM_NAME,
	    SCF_TYPE_ASTRING, cursor, name_attr, NULL) != 0) {
		return (-1);
	}
	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_TM_TYPE,
	    SCF_TYPE_ASTRING, cursor, type_attr, "") != 0) {
		return (-1);
	}
	if (new_bool_prop_from_attr(pg, SCF_PROPERTY_TM_REQUIRED, cursor,
	    required_attr) != 0)
		return (-1);
	return (0);
}

static int
lxml_get_tm_include_values(entity_t *service, pgroup_t *pg,
    xmlNodePtr include_values, const char *prop_name)
{
	boolean_t attach_to_pg = B_FALSE;
	property_t *p;
	int r = 0;
	char *type;

	/* Get the type attribute of the include_values element. */
	type = (char *)xmlGetProp(include_values, (const xmlChar *)type_attr);
	if ((type == NULL) || (*type == 0)) {
		uu_die(gettext("%s element requires a %s attribute in the %s "
		    "service.\n"), include_values->name, type_attr,
		    service->sc_name);
	}

	/* Add the type to the values of the prop_name property. */
	p = internal_property_find(pg, prop_name);
	if (p == NULL)
		attach_to_pg = B_TRUE;
	astring_prop_value(&p, prop_name, type, B_FALSE);
	if (attach_to_pg == B_TRUE) {
		r = internal_attach_property(pg, p);
		if (r != 0)
			internal_property_free(p);
	}
	return (r);
}

#define	RC_MIN		0
#define	RC_MAX		1
#define	RC_COUNT	2

/*
 * Verify that the strings at min and max are valid numeric strings.  Also
 * verify that max is numerically >= min.
 *
 * 0 is returned if the range is valid, and -1 is returned if it is not.
 */
static int
verify_range(entity_t *service, xmlNodePtr range, char *min, char *max)
{
	char *c;
	int i;
	int is_signed = 0;
	int inverted = 0;
	const char *limit[RC_COUNT];
	char *strings[RC_COUNT];
	uint64_t urange[RC_COUNT];	/* unsigned range. */
	int64_t srange[RC_COUNT];	/* signed range. */

	strings[RC_MIN] = min;
	strings[RC_MAX] = max;
	limit[RC_MIN] = min_attr;
	limit[RC_MAX] = max_attr;

	/* See if the range is signed. */
	for (i = 0; (i < RC_COUNT) && (is_signed == 0); i++) {
		c = strings[i];
		while (isspace(*c)) {
			c++;
		}
		if (*c == '-')
			is_signed = 1;
	}

	/* Attempt to convert the strings. */
	for (i = 0; i < RC_COUNT; i++) {
		errno = 0;
		if (is_signed) {
			srange[i] = strtoll(strings[i], &c, 0);
		} else {
			urange[i] = strtoull(strings[i], &c, 0);
		}
		if ((errno != 0) || (c == strings[i]) || (*c != 0)) {
			/* Conversion failed. */
			uu_die(gettext("Unable to convert %s for the %s "
			    "element in service %s.\n"), limit[i],
			    (char *)range->name, service->sc_name);
		}
	}

	/* Make sure that min is <= max */
	if (is_signed) {
		if (srange[RC_MAX] < srange[RC_MIN])
			inverted = 1;
	} else {
		if (urange[RC_MAX] < urange[RC_MIN])
			inverted = 1;
	}
	if (inverted != 0) {
		semerr(gettext("Maximum less than minimum for the %s element "
		    "in service %s.\n"), (char *)range->name,
		    service->sc_name);
		return (-1);
	}

	return (0);
}

/*
 * This, function creates a property named prop_name.  The range element
 * should have two attributes -- min and max.  The property value then
 * becomes the concatenation of their value separated by a comma.  The
 * property is then attached to the property group at pg.
 *
 * If pg already contains a property with a name of prop_name, it is only
 * necessary to create a new value and attach it to the existing property.
 */
static int
lxml_get_tm_range(entity_t *service, pgroup_t *pg, xmlNodePtr range,
    const char *prop_name)
{
	boolean_t attach_to_pg = B_FALSE;
	char *max;
	char *min;
	property_t *p;
	char *prop_value;
	int r = 0;

	/* Get max and min from the XML description. */
	max = (char *)xmlGetProp(range, (xmlChar *)max_attr);
	if ((max == NULL) || (*max == 0)) {
		uu_die(gettext("%s element is missing the %s attribute in "
		    "service %s.\n"), (char *)range->name, max_attr,
		    service->sc_name);
	}
	min = (char *)xmlGetProp(range, (xmlChar *)min_attr);
	if ((min == NULL) || (*min == 0)) {
		uu_die(gettext("%s element is missing the %s attribute in "
		    "service %s.\n"), (char *)range->name, min_attr,
		    service->sc_name);
	}
	if (verify_range(service, range, min, max) != 0) {
		xmlFree(min);
		xmlFree(max);
		return (-1);
	}

	/* Property value is concatenation of min and max. */
	prop_value = safe_malloc(max_scf_value_len + 1);
	if (snprintf(prop_value, max_scf_value_len + 1, "%s,%s", min, max) >=
	    max_scf_value_len + 1) {
		uu_die(gettext("min and max are too long for the %s element "
		    "of %s.\n"), (char *)range->name, service->sc_name);
	}
	xmlFree(min);
	xmlFree(max);

	/*
	 * If necessary create the property and attach it to the property
	 * group.
	 */
	p = internal_property_find(pg, prop_name);
	if (p == NULL)
		attach_to_pg = B_TRUE;
	astring_prop_value(&p, prop_name, prop_value, B_TRUE);
	if (attach_to_pg == B_TRUE) {
		r = internal_attach_property(pg, p);
		if (r != 0) {
			internal_property_free(p);
		}
	}
	return (r);
}

/*
 * Determine how many plain characters are represented by count Base32
 * encoded characters.  5 plain text characters are converted to 8 Base32
 * characters.
 */
static size_t
encoded_count_to_plain(size_t count)
{
	return (5 * ((count + 7) / 8));
}

/*
 * The value element contains 0 or 1 common_name element followed by 0 or 1
 * description element.  It also has a required attribute called "name".
 * The common_name and description are stored as property values in pg.
 * The property names are:
 *	value_<name>_common_name_<lang>
 *	value_<name>_description_<lang>
 *
 * The <name> portion of the preceeding proper names requires more
 * explanation.  Ideally it would just the name attribute of this value
 * element.  Unfortunately, the name attribute can contain characters that
 * are not legal in a property name.  Thus, we base 32 encode the name
 * attribute and use that for <name>.
 *
 * There are cases where the caller needs to know the name, so it is
 * returned through the name_value pointer if it is not NULL.
 *
 * Parameters:
 *	service -	Information about the service that is being
 *			processed.  This function only uses this parameter
 *			for producing error messages.
 *
 *	pg -		The property group to receive the newly created
 *			properties.
 *
 *	value -		Pointer to the value element in the XML tree.
 *
 *	name_value -	Address to receive the value of the name attribute.
 *			The caller must free the memory.
 */
static int
lxml_get_tm_value_element(entity_t *service, pgroup_t *pg, xmlNodePtr value,
    char **name_value)
{
	char *common_name_fmt;
	xmlNodePtr cursor;
	char *description_fmt;
	char *encoded_value = NULL;
	size_t extra;
	char *value_name;
	int r = 0;

	common_name_fmt = safe_malloc(max_scf_name_len + 1);
	description_fmt = safe_malloc(max_scf_name_len + 1);

	/*
	 * Get the value of our name attribute, so that we can use it to
	 * construct property names.
	 */
	value_name = (char *)xmlGetProp(value, (xmlChar *)name_attr);
	/* The value name must be present, but it can be empty. */
	if (value_name == NULL) {
		uu_die(gettext("%s element requires a %s attribute in the %s "
		    "service.\n"), (char *)value->name, name_attr,
		    service->sc_name);
	}

	/*
	 * The value_name may contain characters that are not valid in in a
	 * property name.  So we will encode value_name and then use the
	 * encoded value in the property name.
	 */
	encoded_value = safe_malloc(max_scf_name_len + 1);
	if (scf_encode32(value_name, strlen(value_name), encoded_value,
	    max_scf_name_len + 1, &extra, SCF_ENCODE32_PAD) != 0) {
		extra = encoded_count_to_plain(extra - max_scf_name_len);
		uu_die(gettext("Constructed property name is %u characters "
		    "too long for value \"%s\" in the %s service.\n"),
		    extra, value_name, service->sc_name);
	}
	if ((extra = snprintf(common_name_fmt, max_scf_name_len + 1,
	    VALUE_COMMON_NAME_FMT, SCF_PROPERTY_TM_VALUE_PREFIX,
	    encoded_value)) >= max_scf_name_len + 1) {
		extra = encoded_count_to_plain(extra - max_scf_name_len);
		uu_die(gettext("Name attribute is "
		    "%u characters too long for %s in service %s\n"),
		    extra, (char *)value->name, service->sc_name);
	}
	if ((extra = snprintf(description_fmt, max_scf_name_len + 1,
	    VALUE_DESCRIPTION_FMT, SCF_PROPERTY_TM_VALUE_PREFIX,
	    encoded_value)) >= max_scf_name_len + 1) {
		extra = encoded_count_to_plain(extra - max_scf_name_len);
		uu_die(gettext("Name attribute is "
		    "%u characters too long for %s in service %s\n"),
		    extra, (char *)value->name, service->sc_name);
	}

	for (cursor = value->xmlChildrenNode;
	    cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;
		switch (lxml_xlate_element(cursor->name)) {
		case SC_COMMON_NAME:
			r = lxml_get_all_loctext(service, pg, cursor,
			    common_name_fmt, (const char *)cursor->name);
			break;
		case SC_DESCRIPTION:
			r = lxml_get_all_loctext(service, pg, cursor,
			    description_fmt, (const char *)cursor->name);
			break;
		default:
			uu_die(gettext("\"%s\" is an illegal element in %s "
			    "of service %s\n"), (char *)cursor->name,
			    (char *)value->name, service->sc_name);
		}
		if (r != 0)
			break;
	}

	free(description_fmt);
	free(common_name_fmt);
	if (r == 0) {
		*name_value = safe_strdup(value_name);
	}
	xmlFree(value_name);
	free(encoded_value);
	return (r);
}

static int
lxml_get_tm_choices(entity_t *service, pgroup_t *pg, xmlNodePtr choices)
{
	xmlNodePtr cursor;
	char *name_value;
	property_t *name_prop = NULL;
	int r = 0;

	for (cursor = choices->xmlChildrenNode;
	    (cursor != NULL) && (r == 0);
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;
		switch (lxml_xlate_element(cursor->name)) {
		case SC_INCLUDE_VALUES:
			(void) lxml_get_tm_include_values(service, pg, cursor,
			    SCF_PROPERTY_TM_CHOICES_INCLUDE_VALUES);
			break;
		case SC_RANGE:
			r = lxml_get_tm_range(service, pg, cursor,
			    SCF_PROPERTY_TM_CHOICES_RANGE);
			if (r != 0)
				goto out;
			break;
		case SC_VALUE:
			r = lxml_get_tm_value_element(service, pg, cursor,
			    &name_value);
			if (r == 0) {
				/*
				 * There is no need to free the memory
				 * associated with name_value, because the
				 * property value will end up pointing to
				 * the memory.
				 */
				astring_prop_value(&name_prop,
				    SCF_PROPERTY_TM_CHOICES_NAME, name_value,
				    B_TRUE);
			} else {
				goto out;
			}
			break;
		default:
			uu_die(gettext("%s is an invalid element of "
			    "choices for service %s.\n"),  cursor->name,
			    service->sc_name);
		}
	}

out:
	/* Attach the name property if we created one. */
	if ((r == 0) && (name_prop != NULL)) {
		r = internal_attach_property(pg, name_prop);
	}
	if ((r != 0) && (name_prop != NULL)) {
		internal_property_free(name_prop);
	}

	return (r);
}

static int
lxml_get_tm_constraints(entity_t *service, pgroup_t *pg, xmlNodePtr constraints)
{
	xmlNodePtr cursor;
	char *name_value;
	property_t *name_prop = NULL;
	int r = 0;

	for (cursor = constraints->xmlChildrenNode;
	    (cursor != NULL) && (r == 0);
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;
		switch (lxml_xlate_element(cursor->name)) {
		case SC_RANGE:
			r = lxml_get_tm_range(service, pg, cursor,
			    SCF_PROPERTY_TM_CONSTRAINT_RANGE);
			if (r != 0)
				goto out;
			break;
		case SC_VALUE:
			r = lxml_get_tm_value_element(service, pg, cursor,
			    &name_value);
			if (r == 0) {
				/*
				 * There is no need to free the memory
				 * associated with name_value, because the
				 * property value will end up pointing to
				 * the memory.
				 */
				astring_prop_value(&name_prop,
				    SCF_PROPERTY_TM_CONSTRAINT_NAME, name_value,
				    B_TRUE);
			} else {
				goto out;
			}
			break;
		default:
			uu_die(gettext("%s is an invalid element of "
			    "constraints for service %s.\n"),  cursor->name,
			    service->sc_name);
		}
	}

out:
	/* Attach the name property if we created one. */
	if ((r == 0) && (name_prop != NULL)) {
		r = internal_attach_property(pg, name_prop);
	}
	if ((r != 0) && (name_prop != NULL)) {
		internal_property_free(name_prop);
	}

	return (r);
}

/*
 * The values element contains one or more value elements.
 */
static int
lxml_get_tm_values(entity_t *service, pgroup_t *pg, xmlNodePtr values)
{
	xmlNodePtr cursor;
	char *name_value;
	property_t *name_prop = NULL;
	int r = 0;

	for (cursor = values->xmlChildrenNode;
	    (cursor != NULL) && (r == 0);
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;
		if (lxml_xlate_element(cursor->name) != SC_VALUE) {
			uu_die(gettext("\"%s\" is an illegal element in the "
			    "%s element of %s\n"), (char *)cursor->name,
			    (char *)values->name, service->sc_name);
		}
		r = lxml_get_tm_value_element(service, pg, cursor, &name_value);
		if (r == 0) {
			/*
			 * There is no need to free the memory
			 * associated with name_value, because the
			 * property value will end up pointing to
			 * the memory.
			 */
			astring_prop_value(&name_prop,
			    SCF_PROPERTY_TM_VALUES_NAME, name_value,
			    B_TRUE);
		}
	}

	/* Attach the name property if we created one. */
	if ((r == 0) && (name_prop != NULL)) {
		r = internal_attach_property(pg, name_prop);
	}
	if ((r != 0) && (name_prop != NULL)) {
		internal_property_free(name_prop);
	}

	return (r);
}

/*
 * This function processes a prop_pattern element within a pg_pattern XML
 * element.  First it creates a property group to hold the prop_pattern
 * information.  The name of this property group is the concatenation of:
 *	- SCF_PG_TM_PROP_PATTERN_PREFIX
 *	- The unique part of the property group name of the enclosing
 *	  pg_pattern.  The property group name of the enclosing pg_pattern
 *	  is passed to us in pgpat_name.  The unique part, is the part
 *	  following SCF_PG_TM_PG_PATTERN_PREFIX.
 *	- The name of this prop_pattern element.
 *
 * After creating the property group, the prop_pattern attributes are saved
 * as properties in the PG.  Finally, the prop_pattern elements are
 * processed and added to the PG.
 */
static int
lxml_get_tm_prop_pattern(entity_t *service, xmlNodePtr prop_pattern,
    const char *pgpat_name)
{
	xmlNodePtr cursor;
	int extra;
	pgroup_t *pg;
	property_t *p;
	char *pg_name;
	size_t prefix_len;
	xmlChar *prop_pattern_name;
	int r;
	const char *unique;
	value_t *v;

	/* Find the unique part of the pg_pattern property group name. */
	prefix_len = strlen(SCF_PG_TM_PG_PAT_BASE);
	assert(strncmp(pgpat_name, SCF_PG_TM_PG_PAT_BASE, prefix_len) == 0);
	unique = pgpat_name + prefix_len;

	/*
	 * We need to get the value of the name attribute first.  The
	 * prop_pattern name as well as the name of the enclosing
	 * pg_pattern both constitute part of the name of the property
	 * group that we will create.
	 */
	prop_pattern_name = xmlGetProp(prop_pattern, (xmlChar *)name_attr);
	if ((prop_pattern_name == NULL) || (*prop_pattern_name == 0)) {
		semerr(gettext("prop_pattern name is missing for %s\n"),
		    service->sc_name);
		return (-1);
	}
	if (uu_check_name((const char *)prop_pattern_name,
	    UU_NAME_DOMAIN) != 0) {
		semerr(gettext("prop_pattern name, \"%s\", for %s is not "
		    "valid.\n"), prop_pattern_name, service->sc_name);
		xmlFree(prop_pattern_name);
		return (-1);
	}
	pg_name = safe_malloc(max_scf_name_len + 1);
	if ((extra = snprintf(pg_name, max_scf_name_len + 1, "%s%s_%s",
	    SCF_PG_TM_PROP_PATTERN_PREFIX, unique,
	    (char *)prop_pattern_name)) >= max_scf_name_len + 1) {
		uu_die(gettext("prop_pattern name, \"%s\", for %s is %d "
		    "characters too long\n"), (char *)prop_pattern_name,
		    service->sc_name, extra - max_scf_name_len);
	}

	/*
	 * Create the property group, the property referencing the pg_pattern
	 * name, and add the prop_pattern attributes to the property group.
	 */
	pg = internal_pgroup_create_strict(service, pg_name,
	    SCF_GROUP_TEMPLATE_PROP_PATTERN);
	if (pg == NULL) {
		uu_die(gettext("Property group for prop_pattern, \"%s\", "
		    "already exists in %s\n"), prop_pattern_name,
		    service->sc_name);
	}

	p = internal_property_create(SCF_PROPERTY_TM_PG_PATTERN,
	    SCF_TYPE_ASTRING, 1, safe_strdup(pgpat_name));
	/*
	 * Unfortunately, internal_property_create() does not set the free
	 * function for the value, so we'll set it now.
	 */
	v = uu_list_first(p->sc_property_values);
	v->sc_free = lxml_free_str;
	if (internal_attach_property(pg, p) != 0)
		internal_property_free(p);


	r = lxml_get_prop_pattern_attributes(pg, prop_pattern);
	if (r != 0)
		goto out;

	/*
	 * Now process the elements of prop_pattern
	 */
	for (cursor = prop_pattern->xmlChildrenNode;
	    cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_CARDINALITY:
			r = lxml_get_tm_cardinality(service, pg, cursor);
			if (r != 0)
				goto out;
			break;
		case SC_CHOICES:
			r = lxml_get_tm_choices(service, pg, cursor);
			if (r != 0)
				goto out;
			break;
		case SC_COMMON_NAME:
			(void) lxml_get_all_loctext(service, pg, cursor,
			    COMMON_NAME_FMT, (const char *)cursor->name);
			break;
		case SC_CONSTRAINTS:
			r = lxml_get_tm_constraints(service, pg, cursor);
			if (r != 0)
				goto out;
			break;
		case SC_DESCRIPTION:
			(void) lxml_get_all_loctext(service, pg, cursor,
			    DESCRIPTION_FMT, (const char *)cursor->name);
			break;
		case SC_INTERNAL_SEPARATORS:
			r = lxml_get_tm_internal_seps(service, pg, cursor);
			if (r != 0)
				goto out;
			break;
		case SC_UNITS:
			(void) lxml_get_all_loctext(service, pg, cursor,
			    UNITS_FMT, "units");
			break;
		case SC_VALUES:
			(void) lxml_get_tm_values(service, pg, cursor);
			break;
		case SC_VISIBILITY:
			/*
			 * The visibility element is empty, so we only need
			 * to proccess the value attribute.
			 */
			(void) new_str_prop_from_attr(pg,
			    SCF_PROPERTY_TM_VISIBILITY, SCF_TYPE_ASTRING,
			    cursor, value_attr);
			break;
		default:
			uu_die(gettext("illegal element \"%s\" in prop_pattern "
			    "for service \"%s\"\n"), cursor->name,
			    service->sc_name);
		}
	}

out:
	xmlFree(prop_pattern_name);
	free(pg_name);
	return (r);
}

/*
 * Get the pg_pattern attributes and save them as properties in the
 * property group at pg.  The pg_pattern element accepts four attributes --
 * name, type, required and target.
 */
static int
lxml_get_pg_pattern_attributes(pgroup_t *pg, xmlNodePtr cursor)
{
	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_TM_NAME,
	    SCF_TYPE_ASTRING, cursor, name_attr, NULL) != 0) {
		return (-1);
	}
	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_TM_TYPE,
	    SCF_TYPE_ASTRING, cursor, type_attr, NULL) != 0) {
		return (-1);
	}
	if (new_opt_str_prop_from_attr(pg, SCF_PROPERTY_TM_TARGET,
	    SCF_TYPE_ASTRING, cursor, target_attr, NULL) != 0) {
		return (-1);
	}
	if (new_bool_prop_from_attr(pg, SCF_PROPERTY_TM_REQUIRED, cursor,
	    required_attr) != 0)
		return (-1);
	return (0);
}

/*
 * There are several restrictions on the pg_pattern attributes that cannot
 * be specifed in the service bundle DTD.  This function verifies that
 * those restrictions have been satisfied.  The restrictions are:
 *
 *	- The target attribute may have a value of "instance" only when the
 *	  template block is in a service declaration.
 *
 *	- The target attribute may have a value of "delegate" only when the
 *	  template block applies to a restarter.
 *
 *	- The target attribute may have a value of "all" only when the
 *	  template block applies to the master restarter.
 *
 * The function returns 0 on success and -1 on failure.
 */
static int
verify_pg_pattern_attributes(entity_t *s, pgroup_t *pg)
{
	int is_restarter;
	property_t *target;
	value_t *v;

	/* Find the value of the target property. */
	target = internal_property_find(pg, SCF_PROPERTY_TM_TARGET);
	if (target == NULL) {
		uu_die(gettext("pg_pattern is missing the %s attribute "
		    "in %s\n"), target_attr, s->sc_name);
		return (-1);
	}
	v = uu_list_first(target->sc_property_values);
	assert(v != NULL);
	assert(v->sc_type == SCF_TYPE_ASTRING);

	/*
	 * If target has a value of instance, the template must be in a
	 * service object.
	 */
	if (strcmp(v->sc_u.sc_string, "instance") == 0) {
		if (s->sc_etype != SVCCFG_SERVICE_OBJECT) {
			uu_warn(gettext("pg_pattern %s attribute may only "
			    "have a value of \"instance\" when it is in a "
			    "service declaration.\n"), target_attr);
			return (-1);
		}
	}

	/*
	 * If target has a value of "delegate", the template must be in a
	 * restarter.
	 */
	if (strcmp(v->sc_u.sc_string, "delegate") == 0) {
		is_restarter = 0;
		if ((s->sc_etype == SVCCFG_SERVICE_OBJECT) &&
		    (s->sc_u.sc_service.sc_service_type == SVCCFG_RESTARTER)) {
			is_restarter = 1;
		}
		if ((s->sc_etype == SVCCFG_INSTANCE_OBJECT) &&
		    (s->sc_parent->sc_u.sc_service.sc_service_type ==
		    SVCCFG_RESTARTER)) {
			is_restarter = 1;
		}
		if (is_restarter == 0) {
			uu_warn(gettext("pg_pattern %s attribute has a "
			    "value of \"delegate\" but is not in a "
			    "restarter service\n"), target_attr);
			return (-1);
		}
	}

	/*
	 * If target has a value of "all", the template must be in the
	 * global (SCF_SERVICE_GLOBAL) service.
	 */
	if (strcmp(v->sc_u.sc_string, all_value) == 0) {
		if (s->sc_etype != SVCCFG_SERVICE_OBJECT) {
			uu_warn(gettext("pg_pattern %s attribute has a "
			    "value of \"%s\" but is not in a "
			    "service entity.\n"), target_attr, all_value);
			return (-1);
		}
		if (strcmp(s->sc_fmri, SCF_SERVICE_GLOBAL) != 0) {
			uu_warn(gettext("pg_pattern %s attribute has a "
			    "value of \"%s\" but is in the \"%s\" service.  "
			    "pg_patterns with target \"%s\" are only allowed "
			    "in the global service.\n"),
			    target_attr, all_value, s->sc_fmri, all_value);
			return (-1);
		}
	}

	return (0);
}

static int
lxml_get_tm_pg_pattern(entity_t *service, xmlNodePtr pg_pattern)
{
	xmlNodePtr cursor;
	int out_len;
	xmlChar *name;
	pgroup_t *pg = NULL;
	char *pg_name;
	int r = -1;
	xmlChar *type;

	pg_name = safe_malloc(max_scf_name_len + 1);

	/*
	 * Get the name and type attributes.  Their presence or absence
	 * determines whcih prefix we will use for the property group name.
	 * There are four cases -- neither attribute is present, both are
	 * present, only name is present or only type is present.
	 */
	name = xmlGetProp(pg_pattern, (xmlChar *)name_attr);
	type = xmlGetProp(pg_pattern, (xmlChar *)type_attr);
	if ((name == NULL) || (*name == 0)) {
		if ((type == NULL) || (*type == 0)) {
			/* PG name contains only the prefix in this case */
			if (strlcpy(pg_name, SCF_PG_TM_PG_PATTERN_PREFIX,
			    max_scf_name_len + 1) >= max_scf_name_len + 1) {
				uu_die(gettext("Unable to create pg_pattern "
				    "property for %s\n"), service->sc_name);
			}
		} else {
			/*
			 * If we have a type and no name, the type becomes
			 * part of the pg_pattern property group name.
			 */
			if ((out_len = snprintf(pg_name, max_scf_name_len + 1,
			    "%s%s", SCF_PG_TM_PG_PATTERN_T_PREFIX, type)) >=
			    max_scf_name_len + 1) {
				uu_die(gettext("pg_pattern type is for %s is "
				    "%d bytes too long\n"), service->sc_name,
				    out_len - max_scf_name_len);
			}
		}
	} else {
		const char *prefix;

		/* Make sure that the name is valid. */
		if (uu_check_name((const char *)name, UU_NAME_DOMAIN) != 0) {
			semerr(gettext("pg_pattern name attribute, \"%s\", "
			    "for %s is invalid\n"), name, service->sc_name);
			goto out;
		}

		/*
		 * As long as the pg_pattern has a name, it becomes part of
		 * the name of the pg_pattern property group name.  We
		 * merely need to pick the appropriate prefix.
		 */
		if ((type == NULL) || (*type == 0)) {
			prefix = SCF_PG_TM_PG_PATTERN_N_PREFIX;
		} else {
			prefix = SCF_PG_TM_PG_PATTERN_NT_PREFIX;
		}
		if ((out_len = snprintf(pg_name, max_scf_name_len + 1, "%s%s",
		    prefix, name)) >= max_scf_name_len + 1) {
			uu_die(gettext("pg_pattern property group name "
			    "for %s is %d bytes too long\n"), service->sc_name,
			    out_len - max_scf_name_len);
		}
	}

	/*
	 * Create the property group for holding this pg_pattern
	 * information, and capture the pg_pattern attributes.
	 */
	pg = internal_pgroup_create_strict(service, pg_name,
	    SCF_GROUP_TEMPLATE_PG_PATTERN);
	if (pg == NULL) {
		if ((name == NULL) || (*name == 0)) {
			if ((type == NULL) ||(*type == 0)) {
				semerr(gettext("pg_pattern with empty name and "
				    "type is not unique in %s\n"),
				    service->sc_name);
			} else {
				semerr(gettext("pg_pattern with empty name and "
				    "type \"%s\" is not unique in %s\n"),
				    type, service->sc_name);
			}
		} else {
			if ((type == NULL) || (*type == 0)) {
				semerr(gettext("pg_pattern with name \"%s\" "
				    "and empty type is not unique in %s\n"),
				    name, service->sc_name);
			} else {
				semerr(gettext("pg_pattern with name \"%s\" "
				    "and type \"%s\" is not unique in %s\n"),
				    name, type, service->sc_name);
			}
		}
		goto out;
	}

	/*
	 * Get the pg_pattern attributes from the manifest and verify
	 * that they satisfy our restrictions.
	 */
	r = lxml_get_pg_pattern_attributes(pg, pg_pattern);
	if (r != 0)
		goto out;
	if (verify_pg_pattern_attributes(service, pg) != 0) {
		semerr(gettext("Invalid pg_pattern attributes in %s\n"),
		    service->sc_name);
		r = -1;
		goto out;
	}

	/*
	 * Now process all of the elements of pg_pattern.
	 */
	for (cursor = pg_pattern->xmlChildrenNode;
	    cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		switch (lxml_xlate_element(cursor->name)) {
		case SC_COMMON_NAME:
			(void) lxml_get_all_loctext(service, pg, cursor,
			    COMMON_NAME_FMT, (const char *)cursor->name);
			break;
		case SC_DESCRIPTION:
			(void) lxml_get_all_loctext(service, pg, cursor,
			    DESCRIPTION_FMT, (const char *)cursor->name);
			break;
		case SC_PROP_PATTERN:
			r = lxml_get_tm_prop_pattern(service, cursor,
			    pg_name);
			if (r != 0)
				goto out;
			break;
		default:
			uu_die(gettext("illegal element \"%s\" in pg_pattern "
			    "for service \"%s\"\n"), cursor->name,
			    service->sc_name);
		}
	}

out:
	if ((r != 0) && (pg != NULL)) {
		internal_detach_pgroup(service, pg);
		internal_pgroup_free(pg);
	}
	free(pg_name);
	xmlFree(name);
	xmlFree(type);

	return (r);
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
		case SC_PG_PATTERN:
			if (lxml_get_tm_pg_pattern(service, cursor) != 0)
				return (-1);
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

	i->sc_op = service->sc_op;
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
 * service.  If op is SVCCFG_OP_APPLY (i.e., apply a profile), set the
 * enabled property to override.
 *
 * If op is SVCCFG_OP_APPLY (i.e., apply a profile), do not allow for
 * modification of template data.
 */
static int
lxml_get_instance(entity_t *service, xmlNodePtr inst, bundle_type_t bt,
    svccfg_op_t op)
{
	entity_t *i;
	pgroup_t *pg;
	property_t *p;
	xmlNodePtr cursor;
	xmlChar *enabled;
	int r, e_val;

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

	i->sc_op = op;
	enabled = xmlGetProp(inst, (xmlChar *)enabled_attr);

	if (enabled == NULL) {
		if (bt == SVCCFG_MANIFEST) {
			semerr(gettext("Instance \"%s\" missing attribute "
			    "\"%s\".\n"), i->sc_name, enabled_attr);
			return (-1);
		}
	} else {	/* enabled != NULL */
		if (strcmp(true, (const char *)enabled) != 0 &&
		    strcmp(false, (const char *)enabled) != 0) {
			xmlFree(enabled);
			semerr(gettext("Invalid enabled value\n"));
			return (-1);
		}
		pg = internal_pgroup_new();
		(void) internal_attach_pgroup(i, pg);

		pg->sc_pgroup_name = (char *)scf_pg_general;
		pg->sc_pgroup_type = (char *)scf_group_framework;
		pg->sc_pgroup_flags = 0;

		e_val = (strcmp(true, (const char *)enabled) == 0);
		p = internal_property_create(SCF_PROPERTY_ENABLED,
		    SCF_TYPE_BOOLEAN, 1, (uint64_t)e_val);

		p->sc_property_override = (op == SVCCFG_OP_APPLY);

		(void) internal_attach_property(pg, p);

		xmlFree(enabled);
	}

	/*
	 * Walk its child elements, as appropriate.
	 */
	for (cursor = inst->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

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
			if (op == SVCCFG_OP_APPLY) {
				semerr(gettext("Template data for \"%s\" may "
				    "not be modified in a profile.\n"),
				    i->sc_name);

				return (-1);
			}

			if (lxml_get_template(i, cursor) != 0)
				return (-1);
			break;
		case SC_NOTIFICATION_PARAMETERS:
			if (lxml_get_notification_parameters(i, cursor) != 0)
				return (-1);
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
 * Check to see if the service should allow the upgrade
 * process to handle adding of the manifestfiles linkage.
 *
 * If the service exists and does not have a manifestfiles
 * property group then the upgrade process should handle
 * the service.
 *
 * If the service doesn't exist or the service exists
 * and has a manifestfiles property group then the import
 * process can handle the manifestfiles property group
 * work.
 *
 * This prevents potential cleanup of unaccounted for instances
 * in early manifest import due to upgrade process needing
 * information that has not yet been supplied by manifests
 * that are still located in the /var/svc manifests directory.
 */
static int
lxml_check_upgrade(const char *service)
{
	scf_handle_t	*h = NULL;
	scf_scope_t	*sc = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	int rc = SCF_FAILED;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    (sc = scf_scope_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL)
		goto out;

	if (scf_handle_bind(h) != 0)
		goto out;

	if (scf_handle_get_scope(h, SCF_FMRI_LOCAL_SCOPE, sc) == -1)
		goto out;

	if (scf_scope_get_service(sc, service, svc) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			rc = SCF_SUCCESS;

		goto out;
	}

	if (scf_service_get_pg(svc, SCF_PG_MANIFESTFILES, pg) != SCF_SUCCESS)
		goto out;

	rc = SCF_SUCCESS;
out:
	scf_pg_destroy(pg);
	scf_service_destroy(svc);
	scf_scope_destroy(sc);
	scf_handle_destroy(h);

	return (rc);
}

/*
 * Translate a service element into an internal instance/property tree, added
 * to bundle.
 *
 * If op is SVCCFG_OP_APPLY (i.e., apply a profile), do not allow for
 * modification of template data.
 */
static int
lxml_get_service(bundle_t *bundle, xmlNodePtr svc, svccfg_op_t op)
{
	pgroup_t *pg;
	property_t *p;
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

	version = xmlGetProp(svc, (xmlChar *)version_attr);
	s->sc_u.sc_service.sc_service_version = atol((const char *)version);
	xmlFree(version);

	type = xmlGetProp(svc, (xmlChar *)type_attr);
	s->sc_u.sc_service.sc_service_type = lxml_xlate_service_type(type);
	xmlFree(type);

	/*
	 * Set the global missing type to false before processing the service
	 */
	est->sc_miss_type = B_FALSE;
	s->sc_op = op;

	/*
	 * Now that the service is created create the manifest
	 * property group and add the property value of the service.
	 */
	if (lxml_check_upgrade(s->sc_name) == SCF_SUCCESS &&
	    svc->doc->name != NULL &&
	    bundle->sc_bundle_type == SVCCFG_MANIFEST) {
		char *buf, *base, *fname, *bname;
		size_t	base_sz = 0;

		/*
		 * Must remove the PKG_INSTALL_ROOT, point to the correct
		 * directory after install
		 */
		bname = uu_zalloc(PATH_MAX + 1);
		if (realpath(svc->doc->name, bname) == NULL) {
			uu_die(gettext("Unable to create the real path of the "
			    "manifest file \"%s\" : %d\n"), svc->doc->name,
			    errno);
		}

		base = getenv("PKG_INSTALL_ROOT");
		if (base != NULL && strncmp(bname, base, strlen(base)) == 0) {
			base_sz = strlen(base);
		}
		fname = safe_strdup(bname + base_sz);

		uu_free(bname);
		buf = mhash_filename_to_propname(svc->doc->name, B_FALSE);

		pg = internal_pgroup_create_strict(s, SCF_PG_MANIFESTFILES,
		    SCF_GROUP_FRAMEWORK);

		if (pg == NULL) {
			uu_die(gettext("Property group for prop_pattern, "
			    "\"%s\", already exists in %s\n"),
			    SCF_PG_MANIFESTFILES, s->sc_name);
		}

		p = internal_property_create(buf, SCF_TYPE_ASTRING, 1, fname);

		(void) internal_attach_property(pg, p);
	}

	/*
	 * Walk its child elements, as appropriate.
	 */
	for (cursor = svc->xmlChildrenNode; cursor != NULL;
	    cursor = cursor->next) {
		if (lxml_ignorable_block(cursor))
			continue;

		e = lxml_xlate_element(cursor->name);

		switch (e) {
		case SC_INSTANCE:
			if (lxml_get_instance(s, cursor,
			    bundle->sc_bundle_type, op) != 0)
				return (-1);
			break;
		case SC_TEMPLATE:
			if (op == SVCCFG_OP_APPLY) {
				semerr(gettext("Template data for \"%s\" may "
				    "not be modified in a profile.\n"),
				    s->sc_name);

				return (-1);
			}

			if (lxml_get_template(s, cursor) != 0)
				return (-1);
			break;
		case SC_NOTIFICATION_PARAMETERS:
			if (lxml_get_notification_parameters(s, cursor) != 0)
				return (-1);
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

	/*
	 * Now that the service has been processed set the missing type
	 * for the service.  So that only the services with missing
	 * types are processed.
	 */
	s->sc_miss_type = est->sc_miss_type;
	if (est->sc_miss_type)
		est->sc_miss_type = B_FALSE;

	return (internal_attach_service(bundle, s));
}

#ifdef DEBUG
void
lxml_dump(int g, xmlNodePtr p)
{
	if (p && p->name) {
		(void) printf("%d %s\n", g, p->name);

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
	type = xmlGetProp(subbundle, (xmlChar *)type_attr);
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

	if (((bundle->sc_bundle_name = xmlGetProp(subbundle,
	    (xmlChar *)name_attr)) == NULL) || (*bundle->sc_bundle_name == 0)) {
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
			if (lxml_get_service(bundle, cursor, op) != 0)
				return (-1);
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

	document->name = safe_strdup(filename);

	/*
	 * Verify that this is a document type we understand.
	 */
	if ((dtd = xmlGetIntSubset(document)) == NULL) {
		semerr(gettext("document has no DTD\n"));
		return (-1);
	} else if (dtdpath == NULL && !do_validate) {
		/*
		 * If apply then setup so that some validation
		 * for specific elements can be done.
		 */
		dtdpath = (char *)document->intSubset->SystemID;
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
