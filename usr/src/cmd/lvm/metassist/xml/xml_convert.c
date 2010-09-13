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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "xml_convert.h"

#include <errno.h>
#include <string.h>
#include <libintl.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <locale.h>
#include <unistd.h>
#include "volume_error.h"
#include "volume_output.h"
#include "volume_string.h"

/*
 * IDs for localized messages in the generated command script
 */

#define	CMD_MSG_ENVIRONMENT		"Environment"
#define	CMD_MSG_AMEND_PATH		"Amend PATH"
#define	CMD_MSG_DISK_SET_NAME		"Disk set name"
#define	CMD_MSG_FUNCTIONS		"Functions"
/* CSTYLED */
#define	CMD_MSG_ECHO_AND_EXEC		"Echo (verbose) and exec given command, exit on error"
#define	CMD_MSG_GET_FULL_PATH		"Get full /dev/rdsk path of given slice"
/* CSTYLED */
#define	CMD_MSG_FMTHARD_SPECIAL		"Run fmthard, ignore partboot error, error if output"
#define	CMD_MSG_MAIN			"Main"
#define	CMD_MSG_VERIFY_ROOT		"Verify root"
#define	CMD_MSG_RUN_AS_ROOT		"This script must be run as root."
#define	CMD_MSG_CHECK_FOR_VERBOSE	"Check for verbose option"
#define	CMD_MSG_DOES_DISK_SET_EXIST	"Does the disk set exist?"
#define	CMD_MSG_TAKE_DISK_SET		"Take control of disk set"
#define	CMD_MSG_CREATE_THE_DISK_SET	"Create the disk set"
#define	CMD_MSG_ADD_DISKS_TO_SET	"Add disks to set"
#define	CMD_MSG_FORMAT_SLICES		"Format slices"
#define	CMD_MSG_CREATE			"Create {1} {2}"
#define	CMD_MSG_DOES_EXIST		"Does {1} exist?"
#define	CMD_MSG_ADD_SLICES_TO		"Add slices to {1}"
/* CSTYLED */
#define	CMD_MSG_ASSOCIATE_WITH_HSP	"Associate {1} {2} with hot spare pool {3}"

/*
 * ******************************************************************
 *
 * Data types
 *
 * ******************************************************************
 */

/*
 * Encapsulates the parsing of an XML attribute
 */
typedef struct {

	/* The name of the attribute */
	char *name;

	/*
	 * A function to validate and set the XML attribute value in
	 * the given devconfig_t structure.
	 *
	 * @param	    name
	 *		    the name of the XML attribute
	 *
	 * @param	    value
	 *		    the value of the XML attribute
	 *
	 * @return	    0 if the given value was valid and set
	 *		    successfully, non-zero otherwise.
	 */
	int (*validate_set)(devconfig_t *device, char *name, char *value);

	/*
	 * A function to get the XML attribute value in the given
	 * devconfig_t structure.
	 *
	 * @param	    name
	 *		    the name of the XML attribute
	 *
	 * @param	    value
	 *		    the value of the XML attribute
	 *
	 * @return	    0 if the given value was retrieved
	 *		    successfully, non-zero otherwise.
	 */
	int (*get_as_string)(devconfig_t *device, char *name, char **value);
} attr_t;

/*
 * Encapsulates the parsing of an XML element
 */
typedef struct {
	/* The name of the element */
	char *name;

	/* The type of element to set in the devconfig_t */
	component_type_t type;

	/*
	 * When converting from XML to a devconfig_t hierarchy,
	 * indicates whether to create a new devconfig_t structure in
	 * the hierarchy when this XML element is encountered.
	 */
	boolean_t is_hierarchical;

	/*
	 * If is_hierarchical is B_TRUE, whether to use an existing
	 * devconfig_t structure of this type when this element is
	 * encountered
	 */
	boolean_t singleton;

	/* The valid XML attributes for this element */
	attr_t *attributes;
} element_t;

typedef struct {
	char *msgid;
	char *message;
} l10nmessage_t;

/*
 * ******************************************************************
 *
 * Function prototypes
 *
 * ******************************************************************
 */

static int validate_doc(xmlDocPtr doc, const char *name, const char *systemID);
static int devconfig_to_xml(
    xmlNodePtr parent, element_t elements[], devconfig_t *device);
static int xml_to_devconfig(
    xmlNodePtr cur, element_t elements[], devconfig_t *device);
static int compare_is_a_diskset(void *obj1, void *obj2);
static xmlNodePtr xml_find_node(
    xmlNodePtr node, xmlChar *element, xmlChar *name);
static xmlDocPtr create_localized_message_doc();
static int create_localized_message_file(char **tmpfile);
static int strtobool(char *str, boolean_t *value);
static int ofprintf_terse(void *unused, char *fmt, ...);
static int ofprintf_verbose(void *unused, char *fmt, ...);

static int validate_set_size(
    devconfig_t *volume, char *attr, char *value);
static int validate_set_size_in_blocks(
    devconfig_t *slice, char *attr, char *value);
static int validate_set_diskset_name(
    devconfig_t *diskset, char *attr, char *name);
static int validate_add_available_name(
    devconfig_t *device, char *attr, char *name);
static int validate_add_unavailable_name(
    devconfig_t *device, char *attr, char *name);
static int validate_set_hsp_name(
    devconfig_t *hsp, char *attr, char *name);
static int validate_set_disk_name(
    devconfig_t *disk, char *attr, char *name);
static int validate_set_slice_name(
    devconfig_t *slice, char *attr, char *name);
static int validate_set_slice_start_block(
    devconfig_t *slice, char *attr, char *value);
static int validate_set_volume_name(
    devconfig_t *volume, char *attr, char *name);
static int validate_set_stripe_interlace(
    devconfig_t *stripe, char *attr, char *value);
static int validate_set_stripe_mincomp(
    devconfig_t *stripe, char *attr, char *value);
static int validate_set_stripe_maxcomp(
    devconfig_t *stripe, char *attr, char *value);
static int validate_set_volume_usehsp(
    devconfig_t *volume, char *attr, char *value);
static int validate_set_mirror_nsubmirrors(
    devconfig_t *mirror, char *attr, char *value);
static int validate_set_mirror_read(
    devconfig_t *mirror, char *attr, char *value);
static int validate_set_mirror_write(
    devconfig_t *mirror, char *attr, char *value);
static int validate_set_mirror_passnum(
    devconfig_t *mirror, char *attr, char *value);
static int validate_set_volume_redundancy(
    devconfig_t *volume, char *attr, char *value);
static int validate_set_volume_datapaths(
    devconfig_t *volume, char *attr, char *value);

static int get_as_string_name(
    devconfig_t *device, char *attr, char **value);
static int get_as_string_mirror_passnum(
    devconfig_t *mirror, char *attr, char **value);
static int get_as_string_mirror_read(
    devconfig_t *mirror, char *attr, char **value);
static int get_as_string_mirror_write(
    devconfig_t *mirror, char *attr, char **value);
static int get_as_string_size_in_blocks(
    devconfig_t *device, char *attr, char **value);
static int get_as_string_slice_start_block(
    devconfig_t *slice, char *attr, char **value);
static int get_as_string_stripe_interlace(
    devconfig_t *stripe, char *attr, char **value);

/*
 * ******************************************************************
 *
 * Data
 *
 * ******************************************************************
 */

/* Valid units for the size attribute */
units_t size_units[] = {
	{UNIT_KILOBYTES, BYTES_PER_KILOBYTE},
	{UNIT_MEGABYTES, BYTES_PER_MEGABYTE},
	{UNIT_GIGABYTES, BYTES_PER_GIGABYTE},
	{UNIT_TERABYTES, BYTES_PER_TERABYTE},
	{NULL, 0}
};

/* Valid units for the interlace attribute */
units_t interlace_units[] = {
	{UNIT_BLOCKS, BYTES_PER_BLOCK},
	{UNIT_KILOBYTES, BYTES_PER_KILOBYTE},
	{UNIT_MEGABYTES, BYTES_PER_MEGABYTE},
	{NULL, 0}
};

/* <diskset> attributes */
static attr_t diskset_attrs[] = {
	{ ATTR_NAME, validate_set_diskset_name, get_as_string_name },
	{ NULL, NULL, NULL }
};

/* <available> attributes */
static attr_t available_attrs[] = {
	{ ATTR_NAME, validate_add_available_name, NULL },
	{ NULL, NULL, NULL }
};

/* <unavailable> attributes */
static attr_t unavailable_attrs[] = {
	{ ATTR_NAME, validate_add_unavailable_name, NULL },
	{ NULL, NULL, NULL }
};

/* <hsp> attributes */
static attr_t hsp_attrs[] = {
	{ ATTR_NAME, validate_set_hsp_name, get_as_string_name },
	{ NULL, NULL, NULL }
};

/* <disk> attributes */
static attr_t disk_attrs[] = {
	{ ATTR_NAME, validate_set_disk_name, get_as_string_name },
	{ NULL, NULL, NULL }
};

/* <slice> attributes */
static attr_t slice_attrs[] = {
	{ ATTR_NAME, validate_set_slice_name, get_as_string_name },
	{ ATTR_SIZEINBLOCKS, validate_set_size_in_blocks,
	    get_as_string_size_in_blocks },
	{ ATTR_SLICE_STARTSECTOR, validate_set_slice_start_block,
	    get_as_string_slice_start_block },
	{ NULL, NULL, NULL }
};

/* <stripe> attributes */
static attr_t stripe_attrs[] = {
	{ ATTR_NAME, validate_set_volume_name, get_as_string_name },
	{ ATTR_SIZEINBYTES, validate_set_size, NULL },
	{ ATTR_STRIPE_MINCOMP, validate_set_stripe_mincomp, NULL },
	{ ATTR_STRIPE_MAXCOMP, validate_set_stripe_maxcomp, NULL },
	{ ATTR_STRIPE_INTERLACE, validate_set_stripe_interlace,
	    get_as_string_stripe_interlace },
	{ ATTR_VOLUME_USEHSP, validate_set_volume_usehsp, NULL },
	{ NULL, NULL, NULL }
};

/* <concat> attributes */
static attr_t concat_attrs[] = {
	{ ATTR_NAME,   validate_set_volume_name, get_as_string_name },
	{ ATTR_SIZEINBYTES,   validate_set_size, NULL },
	{ ATTR_VOLUME_USEHSP, validate_set_volume_usehsp, NULL },
	{ NULL, NULL, NULL }
};

/* <mirror> attributes */
static attr_t mirror_attrs[] = {
	{ ATTR_NAME, validate_set_volume_name, get_as_string_name },
	{ ATTR_MIRROR_NSUBMIRRORS, validate_set_mirror_nsubmirrors, NULL },
	{ ATTR_SIZEINBYTES, validate_set_size, NULL },
	{ ATTR_MIRROR_READ, validate_set_mirror_read,
	    get_as_string_mirror_read },
	{ ATTR_MIRROR_WRITE, validate_set_mirror_write,
	    get_as_string_mirror_write },
	{ ATTR_MIRROR_PASSNUM, validate_set_mirror_passnum,
	    get_as_string_mirror_passnum },
	{ ATTR_VOLUME_USEHSP, validate_set_volume_usehsp, NULL },
	{ NULL, NULL, NULL }
};

/* <volume> attributes */
static attr_t volume_attrs[] = {
	{ ATTR_NAME, validate_set_volume_name, get_as_string_name },
	{ ATTR_SIZEINBYTES, validate_set_size, NULL },
	{ ATTR_VOLUME_REDUNDANCY, validate_set_volume_redundancy, NULL },
	{ ATTR_VOLUME_FAULTRECOVERY, validate_set_volume_usehsp, NULL },
	{ ATTR_VOLUME_DATAPATHS, validate_set_volume_datapaths, NULL },
	{ NULL, NULL, NULL }
};

/* volume-request elements */
static element_t request_elements[] = {
	{ ELEMENT_DISKSET, TYPE_DISKSET, B_FALSE, B_FALSE, diskset_attrs },
	{ ELEMENT_AVAILABLE, TYPE_UNKNOWN, B_FALSE, B_FALSE, available_attrs },
	{ ELEMENT_UNAVAILABLE, TYPE_UNKNOWN, B_FALSE, B_FALSE,
	    unavailable_attrs },
	{ ELEMENT_HSP, TYPE_HSP, B_TRUE, B_FALSE, hsp_attrs },
	{ ELEMENT_SLICE, TYPE_SLICE, B_TRUE, B_FALSE, slice_attrs },
	{ ELEMENT_STRIPE, TYPE_STRIPE, B_TRUE, B_FALSE, stripe_attrs },
	{ ELEMENT_CONCAT, TYPE_CONCAT, B_TRUE, B_FALSE, concat_attrs },
	{ ELEMENT_MIRROR, TYPE_MIRROR, B_TRUE, B_FALSE, mirror_attrs },
	{ ELEMENT_VOLUME, TYPE_VOLUME, B_TRUE, B_FALSE, volume_attrs },
	{ NULL, NULL, B_FALSE, B_FALSE, NULL }
};

/* volume-defaults elements */
static element_t default_elements[] = {
	{ ELEMENT_DISKSET, TYPE_DISKSET, B_TRUE, B_FALSE, diskset_attrs },
	{ ELEMENT_AVAILABLE, TYPE_UNKNOWN, B_FALSE, B_TRUE, available_attrs },
	{ ELEMENT_UNAVAILABLE, TYPE_UNKNOWN, B_FALSE, B_TRUE,
	    unavailable_attrs },
	{ ELEMENT_HSP, TYPE_HSP, B_TRUE, B_TRUE, hsp_attrs },
	{ ELEMENT_SLICE, TYPE_SLICE, B_TRUE, B_TRUE, slice_attrs },
	{ ELEMENT_STRIPE, TYPE_STRIPE, B_TRUE, B_TRUE, stripe_attrs },
	{ ELEMENT_CONCAT, TYPE_CONCAT, B_TRUE, B_TRUE, concat_attrs },
	{ ELEMENT_MIRROR, TYPE_MIRROR, B_TRUE, B_TRUE, mirror_attrs },
	{ ELEMENT_VOLUME, TYPE_VOLUME, B_TRUE, B_TRUE, volume_attrs },
	{ NULL, NULL, B_FALSE, B_FALSE, NULL }
};

/* volume-config elements */
static element_t config_elements[] = {
	{ ELEMENT_DISKSET, TYPE_DISKSET, B_FALSE, B_FALSE, diskset_attrs },
	{ ELEMENT_DISK, TYPE_DRIVE, B_TRUE, B_FALSE, disk_attrs },
	{ ELEMENT_SLICE, TYPE_SLICE, B_TRUE, B_FALSE, slice_attrs },
	{ ELEMENT_HSP, TYPE_HSP, B_TRUE, B_FALSE, hsp_attrs },
	{ ELEMENT_STRIPE, TYPE_STRIPE, B_TRUE, B_FALSE, stripe_attrs },
	{ ELEMENT_CONCAT, TYPE_CONCAT, B_TRUE, B_FALSE, concat_attrs },
	{ ELEMENT_MIRROR, TYPE_MIRROR, B_TRUE, B_FALSE, mirror_attrs },
	{ NULL, NULL, B_FALSE, B_FALSE, NULL }
};

/*
 * ******************************************************************
 *
 * External functions
 *
 * ******************************************************************
 */

/*
 * Initialize the XML parser, setting defaults across all XML
 * routines.
 */
void
init_xml()
{
	/* COMPAT: Do not generate nodes for formatting spaces */
	LIBXML_TEST_VERSION
	xmlKeepBlanksDefault(0);

	/* Turn on line numbers for debugging */
	xmlLineNumbersDefault(1);

	/* Substitute entities as files are parsed */
	xmlSubstituteEntitiesDefault(1);

	/* Don't load external entity subsets */
	xmlLoadExtDtdDefaultValue = 0;

	/* Don't validate against DTD by default */
	xmlDoValidityCheckingDefaultValue = 0;

	/* Set up output handlers for XML parsing */
	xmlDefaultSAXHandler.warning = (warningSAXFunc)ofprintf_verbose;
	xmlDefaultSAXHandler.error  = (errorSAXFunc)ofprintf_terse;
	xmlDefaultSAXHandler.fatalError = (fatalErrorSAXFunc)ofprintf_terse;
}

/*
 * Clean up any remaining structures before exiting.
 */
void
cleanup_xml()
{
	xsltCleanupGlobals();
	xmlCleanupParser();
}

/*
 * Converts a volume-request XML document into a request_t.
 *
 * @param       doc
 *		an existing volume-request XML document
 *
 * @param       request
 *		RETURN: a new request_t which must be freed via
 *		free_request
 *
 * @return      0 on success, non-zero otherwise.
 */
int
xml_to_request(
	xmlDocPtr doc,
	request_t **request)
{
	int error = 0;

	*request = NULL;

	/* Validate doc against known DTD */
	if ((error = validate_doc(
	    doc, ELEMENT_VOLUMEREQUEST, VOLUME_REQUEST_DTD_LOC)) == 0) {

	    /* Create a request */
	    if ((error = new_request(request)) == 0) {

		/* Convert the XML doc into a request_t */
		error = xml_to_devconfig(xmlDocGetRootElement(doc),
		    request_elements, request_get_diskset_req(*request));
	    }
	}

	return (error);
}

/*
 * Converts a volume-defaults XML document into a defaults_t.
 *
 * @param       doc
 *		an existing volume-defaults XML document
 *
 * @param       defaults
 *		RETURN: a new defaults_t which must be freed via
 *		free_defaults
 *
 * @return      0 on success, non-zero otherwise.
 */
int
xml_to_defaults(
	xmlDocPtr doc,
	defaults_t **defaults)
{
	int error = 0;

	*defaults = NULL;

	/* Validate doc against known DTD */
	if ((error = validate_doc(doc, ELEMENT_VOLUMEDEFAULTS,
	    VOLUME_DEFAULTS_DTD_LOC)) == 0) {

	    /* Create request defaults */
	    if ((error = new_defaults(defaults)) == 0) {

		devconfig_t *global;

		/* Get defaults for all disk sets */
		if ((error = defaults_get_diskset_by_name(
		    *defaults, NULL, &global)) == 0) {

		    /* Populate the global devconfig_t from the XML doc */
		    if ((error = xml_to_devconfig(xmlDocGetRootElement(doc),
			default_elements, global)) == 0) {

			/* Get the components of the global devconfig_t */
			dlist_t *list = devconfig_get_components(global);

			/*
			 * Move all named disk set settings out from
			 * under global settings
			 */
			/* CONSTANTCONDITION */
			while (1) {
			    dlist_t *removed = NULL;
			    devconfig_t *component;

			    /* Remove named disk set from under global */
			    list = dlist_remove_equivalent_item(
				list, NULL, compare_is_a_diskset, &removed);

			    if (removed == NULL) {
				/* No named disk set found */
				break;
			    }

			    component = removed->obj;

			    /* Append named disk set to disk set list */
			    defaults_set_disksets(*defaults,
				dlist_append(dlist_new_item(component),
				defaults_get_disksets(*defaults), AT_TAIL));
			}
		    }
		}
	    }
	}

	return (error);
}

/*
 * Converts a volume-config XML document into a devconfig_t.
 *
 * @param       doc
 *		an existing volume-config XML document
 *
 * @param       config
 *		RETURN: a new devconfig_t which must be freed via
 *		free_devconfig
 *
 * @return      0 on success, non-zero otherwise.
 */
int
xml_to_config(
	xmlDocPtr doc,
	devconfig_t **config)
{
	int error = 0;

	*config = NULL;

	/* Validate doc against known DTD */
	if ((error = validate_doc(
	    doc, ELEMENT_VOLUMECONFIG, VOLUME_CONFIG_DTD_LOC)) == 0) {

	    /* Create a devconfig_t */
	    if ((error = new_devconfig(config, TYPE_DISKSET)) == 0) {

		/* Populate the devconfig_t from the XML doc */
		error = xml_to_devconfig(
		    xmlDocGetRootElement(doc), config_elements, *config);
	    }
	}

	return (error);
}

/*
 * Converts a devconfig_t into a volume-config XML document.
 *
 * @param       config
 *		an existing devconfig_t representing a volume
 *		configuration.
 *
 * @param       doc
 *		RETURN: a new volume-config XML document which must be
 *		freed via xmlFreeDoc
 *
 * @return      0 on success, non-zero otherwise.
 */
int
config_to_xml(
	devconfig_t *config,
	xmlDocPtr *doc)
{
	xmlNodePtr root;
	int error = 0;

	/* Create the XML document */
	*doc = xmlNewDoc((xmlChar *)"1.0");

	/* Create the root node */
	root = xmlNewDocNode(
	    *doc, NULL, (xmlChar *)ELEMENT_VOLUMECONFIG, NULL);
	xmlAddChild((xmlNodePtr)*doc, (xmlNodePtr)root);

	/* Create sub-nodes from the config devconfig_t */
	if ((error = devconfig_to_xml(root, config_elements, config)) == 0) {

	    /* Add DTD node and validate */
	    error = validate_doc(
		*doc, ELEMENT_VOLUMECONFIG, VOLUME_CONFIG_DTD_LOC);
	}

	if (error) {
	    xmlFreeDoc(*doc);
	}

	return (error);
}

/*
 * Converts a volume-config XML document into a Bourne shell script.
 *
 * @param       doc
 *		an existing volume-config XML document
 *
 * @param       commands
 *		RETURN: a new char* which must be freed
 *
 * @return      0 on success, non-zero otherwise.
 */
int
xml_to_commands(
	xmlDocPtr doc,
	char **commands)
{
	char *tmpfile = NULL;
	int error = 0;
	xsltStylesheetPtr style = NULL;

	/* Read in XSL stylesheet as a normal XML document */
	xmlDocPtr xsl_doc = xmlSAXParseFile((xmlSAXHandlerPtr)
	    &xmlDefaultSAXHandler, VOLUME_COMMAND_XSL_LOC, 0);

	if (xsl_doc != NULL && xsl_doc->xmlChildrenNode != NULL) {

		/*
		 * Find the "msgfile" variable node.  This is where
		 * we'll set the location of the file we'll create
		 * containing the localized messages.
		 */
	    xmlNodePtr msgfile_node = xml_find_node(
		xmlDocGetRootElement(xsl_doc), (xmlChar *)ELEMENT_VARIABLE,
		(xmlChar *)NAME_L10N_MESSAGE_FILE);

		/*
		 * Find the "lang" node.  This is where we'll set the
		 * current locale.
		 */
	    xmlNodePtr lang_node = xml_find_node(xmlDocGetRootElement(xsl_doc),
		(xmlChar *)ELEMENT_PARAM, (xmlChar *)NAME_LANG);

		/*
		 * Ignore if the nodes are not found -- the script
		 * will default to the C locale.
		 */
	    if (msgfile_node != NULL && lang_node != NULL) {
		/* Get/set current locale in the "lang" node */
		char *locale = setlocale(LC_MESSAGES, NULL);
		xmlNodeSetContent(lang_node, (xmlChar *)locale);

		/* Write localized messages to a temporary file */
		if ((error = create_localized_message_file(&tmpfile)) == 0) {

		    char *newsel;

		    /* Clear current value of select attribute, if any */
		    xmlChar *cursel = xmlGetProp(
			msgfile_node, (xmlChar *)ATTR_SELECT);
		    if (cursel != NULL) {
			xmlFree(cursel);
		    }

			/*
			 * The select attribute calls the XSLT function
			 * document() to load an external XML file
			 */
		    newsel = stralloccat(3, "document('", tmpfile, "')");

		    if (newsel == NULL) {
			volume_set_error(gettext("out of memory"));
			error = -1;
		    } else {

			/* Set the new value of the select attribute */
			xmlSetProp(msgfile_node,
			    (xmlChar *)ATTR_SELECT, (xmlChar *)newsel);

			free(newsel);
		    }
		}
	    }

	    if (error == 0) {
		style = xsltParseStylesheetDoc(xsl_doc);
	    }
	}

	if (style == NULL) {
	    volume_set_error(
		gettext("could not load stylesheet from %s"),
		VOLUME_COMMAND_XSL_LOC);
	    error = -1;
	} else {

	    xmlDocPtr result = xsltApplyStylesheet(style, doc, NULL);

	    if (result == NULL) {
		volume_set_error(
		    gettext("could not apply stylesheet to volume-config"));
		error = -1;
	    } else {
		int length;

		if (xsltSaveResultToString((xmlChar **)commands,
		    &length, result, style) == -1) {
		    error = ENOMEM;
		}
	    }

	    xsltFreeStylesheet(style);
	}

	if (tmpfile != NULL) {
	    /* Ignore failure */
	    unlink(tmpfile);

	    free(tmpfile);
	}

	return (error);
}

/*
 * ******************************************************************
 *
 * Static functions
 *
 * ******************************************************************
 */

/*
 * Sets the external DTD node in the given XML document and then
 * validates it.
 *
 * @param       doc
 *		an existing XML document
 *
 * @param       name
 *		the expected root element name of the XML document
 *
 * @param       systemID
 *		the location of the DTD
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_doc(
	xmlDocPtr doc,
	const char *name,
	const char *systemID)
{
	xmlValidCtxt context;
	xmlDtdPtr dtd;

	if (doc == NULL) {
	    volume_set_error(gettext("NULL %s document"), name);
	    return (-1);
	}

	/*
	 * Assume that we can't trust any DTD but our own.
	 */

	/* Was a DTD (external or internal) included in the document? */
	if ((dtd = xmlGetIntSubset(doc)) != NULL) {
	    /* Remove the DTD node */
	    oprintf(OUTPUT_DEBUG, gettext("Removing DTD from %s\n"), name);
	    xmlUnlinkNode((xmlNodePtr)dtd);
	    xmlFreeDtd(dtd);
	}

	/* Create the (external) DTD node */
	oprintf(OUTPUT_DEBUG,
	    gettext("Creating new external DTD for %s\n"), name);
	dtd = xmlCreateIntSubset(
	    doc, (xmlChar *)name, NULL, (xmlChar *)systemID);
	if (dtd == NULL) {
	    volume_set_error(
		gettext("could not create DTD node from %s"), systemID);
	    return (-1);
	}

	/* Validate against DTD */
	oprintf(OUTPUT_DEBUG, gettext("Validating %s against DTD\n"), name);
	context.userData = NULL;
	context.error = (xmlValidityErrorFunc)ofprintf_terse;
	context.warning = (xmlValidityWarningFunc)ofprintf_terse;
	if (!xmlValidateDocument(&context, doc)) {
	    volume_set_error(gettext("invalid %s"), name);
	    return (-1);
	}

	return (0);
}

/*
 * Converts a devconfig_t into an XML node subject to the rules in
 * the given element_t array.
 *
 * @param       parent
 *		the XML node to which to add new XML nodes resulting
 *		from conversion of the given devconfig_t
 *
 * @param       elements
 *		the element_ts that describe the structure of the XML
 *		document and govern the conversion of the given
 *		devconfig_t
 *
 * @param       device
 *		the devconfig_t to convert
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
devconfig_to_xml(
	xmlNodePtr parent,
	element_t elements[],
	devconfig_t *device)
{
	int i;
	int error = 0;
	xmlNodePtr node = NULL;

	/* Get device type */
	component_type_t type;
	if ((error = devconfig_get_type(device, &type)) != 0) {
	    return (error);
	}

	/* Search for this element definition */
	for (i = 0; elements[i].name != NULL; i++) {
	    element_t *element = &(elements[i]);

	    if (element->type == type) {
		int j;
		char **array;
		dlist_t *components;

		oprintf(OUTPUT_DEBUG, gettext("Element: %s\n"),
		    devconfig_type_to_str(type));

		/* Create the XML node */
		node = xmlNewChild(
		    parent, NULL, (xmlChar *)element->name, NULL);

		/* For each attribute defined for this element... */
		for (j = 0; element->attributes[j].name != NULL; j++) {
		    attr_t *attribute = &(element->attributes[j]);
		    char *value;

		    /* Is there a valid accessor for this attribute? */
		    if (attribute->get_as_string != NULL) {

			/* Get the attribute value from the device */
			switch (error = attribute->get_as_string(
			    device, attribute->name, &value)) {

			    /* Attribute is set in this device */
			    case 0:
				oprintf(OUTPUT_DEBUG, "    %s: %s\n",
				    attribute->name, value);

				/* Set the value in the XML node */
				xmlSetProp(node, (uchar_t *)attribute->name,
				    (uchar_t *)value);
				free(value);

			    /* FALLTHROUGH */

			    /* Attribute is not set in this device */
			    case ERR_ATTR_UNSET:

				error = 0;
				break;

			    /* Error */
			    default:
				return (error);
			}
		    }
		}

		/* Is this node hierarchical? */
		if (element->is_hierarchical == B_FALSE) {
		    node = parent;
		}

		/* Create <available> nodes */
		array = devconfig_get_available(device);
		if (array != NULL) {
		    for (j = 0; array[j] != NULL; j++) {
			xmlNodePtr child = xmlNewChild(
			    node, NULL, (xmlChar *)ELEMENT_AVAILABLE, NULL);
			xmlSetProp(child,
			    (xmlChar *)ATTR_NAME, (xmlChar *)array[j]);
		    }
		}

		/* Create <unavailable> nodes */
		array = devconfig_get_unavailable(device);
		if (array != NULL) {
		    for (j = 0; array[j] != NULL; j++) {
			xmlNodePtr child = xmlNewChild(
			    node, NULL, (xmlChar *)ELEMENT_UNAVAILABLE, NULL);
			xmlSetProp(child,
			    (xmlChar *)ATTR_NAME, (xmlChar *)array[j]);
		    }
		}

		/*
		 * Recursively convert subcomponents of this device to
		 * XML, taking care to encode them in the order
		 * specified in the element_t list (which should
		 * mirror what's expected by the DTD).
		 */

		/* For each element type... */
		for (j = 0; elements[j].name != NULL; j++) {

		    /* For each component of this device... */
		    for (components = devconfig_get_components(device);
			components != NULL && error == 0;
			components = components->next) {

			devconfig_t *component = (devconfig_t *)components->obj;
			component_type_t t;

			/* Are the types the same? */
			if ((error = devconfig_get_type(component, &t)) != 0) {
			    return (error);
			} else {
			    if (elements[j].type == t) {
				/* Encode child */
				error = devconfig_to_xml(
				    node, elements, component);
			    }
			}
		    }
		}

		/* Element found */
		break;
	    }
	}

	/* Was this device successfully converted? */
	if (node == NULL) {
	    volume_set_error(
		gettext("can't convert device of type \"%s\" to XML element"),
		devconfig_type_to_str(type));
	    error = -1;
	}

	return (error);
}

/*
 * Converts an XML node into a devconfig_t subject to the rules in
 * the given element_t array.
 *
 * @param       cure
 *		the existing XML node to convert
 *
 * @param       elements
 *		the element_ts that describe the structure of the XML
 *		document and govern the conversion of the given XML
 *		node
 *
 * @param       device
 *		the devconfig_t node to which to add new devconfig_ts
 *		resulting from conversion of the given XML node
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
xml_to_devconfig(
	xmlNodePtr cur,
	element_t elements[],
	devconfig_t *device)
{
	int error = 0;

	/* For each child node... */
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
	    int i;
	    boolean_t parsed_elem = B_FALSE;

	    /* Search for this element definition */
	    for (i = 0; elements[i].name != NULL; i++) {
		element_t *element = &(elements[i]);

		if (xmlStrcmp(cur->name, (xmlChar *)element->name) == 0) {
		    int j;
		    devconfig_t *component = NULL;

		    /* Flag that this element has been parsed */
		    parsed_elem = B_TRUE;

		    oprintf(OUTPUT_DEBUG, gettext("line %d: Element <%s>\n"),
			    XML_GET_LINE(cur), cur->name);

		    /* Should a new device be created for this element? */
		    if (element->is_hierarchical == B_TRUE) {

			/* Should we use an existing device of this type? */
			if (element->singleton) {
			    devconfig_get_component(
				device, element->type, &component, B_FALSE);
			}

			if (component == NULL) {
			    oprintf(OUTPUT_DEBUG,
				gettext("Creating new device\n"));

			    /* Create device of this type */
			    if ((error = new_devconfig(
				    &component, element->type)) != 0) {
				return (error);
			    }

			    /* Add component to the toplevel device */
			    devconfig_set_components(
				device, dlist_append(dlist_new_item(component),
				devconfig_get_components(device), AT_TAIL));
			}
		    } else {
			component = device;
		    }

		    /* For each attribute defined for this element... */
		    for (j = 0; element->attributes[j].name != NULL; j++) {
			attr_t *attribute = &(element->attributes[j]);

			/* Get the value of this attribute */
			char *value = (char *)
			    xmlGetProp(cur, (xmlChar *)attribute->name);

			/* Was this attribute specified? */
			if (value != NULL) {
			    oprintf(OUTPUT_DEBUG,
				gettext("line %d:\tAttribute %s=%s\n"),
				XML_GET_LINE(cur), attribute->name, value);

			    /* Set this value in the device */
			    if ((error = attribute->validate_set(
				component, attribute->name, value)) != 0) {
				return (error);
			    }
			}
		    }

		    /* Get recursive sub-elements */
		    if ((error = xml_to_devconfig(
			cur, elements, component)) != 0) {
			return (error);
		    }

		    /* Element found */
		    break;
		}
	    }


	    /* Make sure all non-text/comment elements were parsed */
	    if (parsed_elem == B_FALSE &&
		xmlStrcmp(cur->name, (xmlChar *)ELEMENT_TEXT) != 0 &&
		xmlStrcmp(cur->name, (xmlChar *)ELEMENT_COMMENT) != 0) {

		oprintf(OUTPUT_DEBUG, gettext("Element <%s> NOT PARSED!!!\n"),
		    cur->name);
	    }
	}

	return (0);
}

/*
 * Returns 0 if obj2 (devconfig_t *) is a disk set, 1 otherwise.
 */
static int
compare_is_a_diskset(
	void *obj1,
	void *obj2)
{
	return (devconfig_isA(
	    (devconfig_t *)obj2, TYPE_DISKSET) == B_TRUE ? 0 : 1);
}

/*
 * Recursively searches the given xmlNodePtr for an element of the
 * specified type and name.
 *
 * @param       node
 *              the root node to search
 *
 * @param       element
 *              the name of the element type
 *
 * @param       name
 *              the value of the name attribute
 *
 * @return      a valid xmlNodePtr if an element of the specified
 *              type and name was found, NULL otherwise.
 */
static xmlNodePtr
xml_find_node(
	xmlNodePtr node,
	xmlChar *element,
	xmlChar *name)
{
	xmlNodePtr child;

	/* Is the element the right type? */
	if (xmlStrcmp(element, node->name) == 0 &&

	    /* Does this element's name attribute match? */
	    xmlStrcmp(name, xmlGetProp(node, (xmlChar *)ATTR_NAME)) == 0) {

	    return (node);
	}

	/* Check child nodes */
	for (child = node->xmlChildrenNode; child != NULL;
	    child = child->next) {
	    xmlNodePtr found = xml_find_node(child, element, name);

	    if (found != NULL) {
		return (found);
	    }
	}

	return (NULL);
}

/*
 * Creates an XML document containing all of the localized message
 * strings for the generated command script.
 *
 * @return      a xmlDocPtr which must be freed via xmlFreeDoc
 */
static xmlDocPtr
create_localized_message_doc()
{
	int i;
	char *locale;
	xmlDocPtr doc;
	xmlNodePtr root;
	l10nmessage_t _cmd_messages[21];

	/* Create the XML document */
	doc = xmlNewDoc((xmlChar *)"1.0");

	/* Create the root node */
	root = xmlNewDocNode(
	    doc, NULL, (xmlChar *)ELEMENT_L10N, NULL);
	xmlAddChild((xmlNodePtr) doc, (xmlNodePtr)root);

	_cmd_messages[0].msgid = CMD_MSG_ENVIRONMENT;
	_cmd_messages[0].message = gettext(CMD_MSG_ENVIRONMENT);
	_cmd_messages[1].msgid = CMD_MSG_AMEND_PATH;
	_cmd_messages[1].message = gettext(CMD_MSG_AMEND_PATH);
	_cmd_messages[2].msgid = CMD_MSG_DISK_SET_NAME;
	_cmd_messages[2].message = gettext(CMD_MSG_DISK_SET_NAME);
	_cmd_messages[3].msgid = CMD_MSG_FUNCTIONS;
	_cmd_messages[3].message = gettext(CMD_MSG_FUNCTIONS);
	_cmd_messages[4].msgid = CMD_MSG_ECHO_AND_EXEC;
	_cmd_messages[4].message = gettext(CMD_MSG_ECHO_AND_EXEC);
	_cmd_messages[5].msgid = CMD_MSG_FMTHARD_SPECIAL;
	_cmd_messages[5].message = gettext(CMD_MSG_FMTHARD_SPECIAL);
	_cmd_messages[6].msgid = CMD_MSG_GET_FULL_PATH;
	_cmd_messages[6].message = gettext(CMD_MSG_GET_FULL_PATH);
	_cmd_messages[7].msgid = CMD_MSG_MAIN;
	_cmd_messages[7].message = gettext(CMD_MSG_MAIN);
	_cmd_messages[8].msgid = CMD_MSG_VERIFY_ROOT;
	_cmd_messages[8].message = gettext(CMD_MSG_VERIFY_ROOT);
	_cmd_messages[9].msgid = CMD_MSG_RUN_AS_ROOT;
	_cmd_messages[9].message = gettext(CMD_MSG_RUN_AS_ROOT);
	_cmd_messages[10].msgid = CMD_MSG_CHECK_FOR_VERBOSE;
	_cmd_messages[10].message = gettext(CMD_MSG_CHECK_FOR_VERBOSE);
	_cmd_messages[11].msgid = (CMD_MSG_DOES_DISK_SET_EXIST);
	_cmd_messages[11].message = gettext(CMD_MSG_DOES_DISK_SET_EXIST);
	_cmd_messages[12].msgid = (CMD_MSG_TAKE_DISK_SET);
	_cmd_messages[12].message = gettext(CMD_MSG_TAKE_DISK_SET);
	_cmd_messages[13].msgid = (CMD_MSG_CREATE_THE_DISK_SET);
	_cmd_messages[13].message = gettext(CMD_MSG_CREATE_THE_DISK_SET);
	_cmd_messages[14].msgid = (CMD_MSG_ADD_DISKS_TO_SET);
	_cmd_messages[14].message = gettext(CMD_MSG_ADD_DISKS_TO_SET);
	_cmd_messages[15].msgid = (CMD_MSG_FORMAT_SLICES);
	_cmd_messages[15].message = gettext(CMD_MSG_FORMAT_SLICES);
	_cmd_messages[16].msgid = (CMD_MSG_CREATE);
	_cmd_messages[16].message = gettext(CMD_MSG_CREATE);
	_cmd_messages[17].msgid = (CMD_MSG_DOES_EXIST);
	_cmd_messages[17].message = gettext(CMD_MSG_DOES_EXIST);
	_cmd_messages[18].msgid = (CMD_MSG_ADD_SLICES_TO);
	_cmd_messages[18].message = gettext(CMD_MSG_ADD_SLICES_TO);
	_cmd_messages[19].msgid = (CMD_MSG_ASSOCIATE_WITH_HSP);
	_cmd_messages[19].message = gettext(CMD_MSG_ASSOCIATE_WITH_HSP);
	_cmd_messages[20].msgid = NULL;

	/* Get/set current locale in the "lang" node */
	locale = setlocale(LC_MESSAGES, NULL);

	/* Add localized <message> elements to stylesheet */
	for (i = 0; _cmd_messages[i].msgid != NULL; i++) {
	    xmlNsPtr ns = xmlNewNs(NULL, NULL, NULL);

	    xmlNodePtr node = xmlNewTextChild(
		root, ns, (xmlChar *)ELEMENT_MESSAGE,
		(xmlChar *)_cmd_messages[i].message);
	    /* Lang attribute */
	    xmlSetProp(node,
		(xmlChar *)ATTR_LANG, (xmlChar *)locale);

	    /* Message ID attribute */
	    xmlSetProp(node, (xmlChar *)ATTR_MESSAGEID,
		(xmlChar *)_cmd_messages[i].msgid);
	}

	if (get_max_verbosity() >= OUTPUT_DEBUG) {
	    xmlChar *text;
	    /* Get the text dump */
	    xmlDocDumpFormatMemory(doc, &text, NULL, 1);
	    oprintf(OUTPUT_DEBUG,
		gettext("Generated message file:\n%s"), text);
	    xmlFree(text);
	}

	return (doc);
}

/*
 * Creates a temporary XML file containing all of the localized
 * message strings for the generated command script.
 *
 * @param       tmpfile
 *		RETURN: the name of the temporary XML file
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
create_localized_message_file(
	char **tmpfile)
{
	int error = 0;

	/*
	 * Create temporary file name -- "XXXXXX" is replaced with
	 * unique char sequence by mkstemp()
	 */
	*tmpfile = stralloccat(3, "/tmp/", ELEMENT_L10N, "XXXXXX");

	if (*tmpfile == NULL) {
	    volume_set_error(gettext("out of memory"));
	    error = -1;
	} else {
	    int fildes;
	    FILE *msgfile = NULL;

	    /* Open temp file */
	    if ((fildes = mkstemp(*tmpfile)) != -1) {
		msgfile = fdopen(fildes, "w");
	    }

	    if (msgfile == NULL) {
		volume_set_error(gettext(
		    "could not open file for writing: %s"), *tmpfile);
		error = -1;
	    } else {

		xmlChar *text;
		xmlDocPtr message_doc = create_localized_message_doc();
		xmlDocDumpFormatMemory(message_doc, &text, NULL, 1);

		if (fprintf(msgfile, "%s", text) < 0) {
		    volume_set_error(gettext(
			"could not create localized message file: %s"),
			*tmpfile);
		    error = -1;
		}

		xmlFree(text);
		xmlFreeDoc(message_doc);
	    }

	    fclose(msgfile);
	}

	return (error);
}

/*
 * Converts the given string into a boolean.  The string must be
 * either VALID_ATTR_TRUE or VALID_ATTR_FALSE.
 *
 * @param       str
 *              the string to convert
 *
 * @param       bool
 *              the addr of the boolean_t
 *
 * @return      0 if the given string could be converted to a boolean
 *              non-zero otherwise.
 */
static int
strtobool(
	char *str,
	boolean_t *value)
{
	int error = 0;

	if (strcmp(str, VALID_ATTR_TRUE) == 0) {
	    *value = B_TRUE;
	} else

	if (strcmp(str, VALID_ATTR_FALSE) == 0) {
	    *value = B_FALSE;
	} else

	    error = -1;

	return (error);
}

/*
 * Wrapper for oprintf with a OUTPUT_TERSE level of verbosity.
 * Provides an fprintf-like syntax to enable use as substitute output
 * handler for man of the XML commands.
 *
 * @param       unused
 *		unused, in favor of the FILE* passed to
 *		set_max_verbosity().
 *
 * @param       fmt
 *		a printf-style format string
 *
 * @return      the number of characters output
 */
static int
ofprintf_terse(
	void *unused,
	char *fmt,
	...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = oprintf_va(OUTPUT_TERSE, fmt, ap);
	va_end(ap);

	return (ret);
}

/*
 * Wrapper for oprintf with a OUTPUT_VERBOSE level of verbosity.
 * Provides an fprintf-like syntax to enable use as substitute output
 * handler for man of the XML commands.
 *
 * @param       unused
 *		unused, in favor of the FILE* passed to
 *		set_max_verbosity().
 *
 * @param       fmt
 *		a printf-style format string
 *
 * @return      the number of characters output
 */
static int
ofprintf_verbose(
	void *unused,
	char *fmt,
	...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = oprintf_va(OUTPUT_VERBOSE, fmt, ap);
	va_end(ap);

	return (ret);
}

/*
 * ******************************************************************
 *
 * XML attribute validators/mutators
 *
 * These functions convert the given XML attribute string to the
 * appropriate data type, and then pass it on to the appropriate
 * devconfig_t mutator.  A non-zero status is returned if the given
 * string could not be converted or was invalid.
 *
 * ******************************************************************
 */

/*
 * Validate and set the size attribute in the given volume
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the size
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_size(
	devconfig_t *volume,
	char *attr,
	char *value)
{
	int error;
	uint64_t size = 0;

	/* Convert size string to bytes */
	if ((error = sizestr_to_bytes(value, &size, size_units)) != 0) {
	    return (error);
	}

	/* Set size in volume */
	return (devconfig_set_size(volume, size));
}

/*
 * Validate and set the size_in_blocks attribute in the given slice
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the size_in_blocks
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_size_in_blocks(
	devconfig_t *slice,
	char *attr,
	char *value)
{
	long long size;

	/* Convert string to long long */
	if (sscanf(value, "%lld", &size) != 1) {
	    volume_set_error(gettext("%s: invalid size in blocks"), value);
	    return (-1);
	}

	/* Set the number of submirrors in the slice */
	return (devconfig_set_size_in_blocks(slice, (uint64_t)size));
}

/*
 * Validate and set the name attribute in the given diskset
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_diskset_name(
	devconfig_t *diskset,
	char *attr,
	char *name)
{
	return (devconfig_set_diskset_name(diskset, name));
}

/*
 * Validate and add the given name to the list of available devices in
 * the given volume devconfig_t.
 *
 * @param       device
 *		the devconfig_t whose available device list to modify
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_add_available_name(
	devconfig_t *device,
	char *attr,
	char *name)
{
	char **available;

	/* Get available devices for this device */
	available = devconfig_get_available(device);

	/* Try to add name to array via realloc */
	if ((available = append_to_string_array(available, name)) == NULL) {
	    return (ENOMEM);
	}

	/* Set available devices in the device */
	devconfig_set_available(device, available);

	return (0);
}

/*
 * Validate and add the given name to the list of unavailable devices
 * in the given volume devconfig_t.
 *
 * @param       device
 *		the devconfig_t whose unavailable device list to modify
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_add_unavailable_name(
	devconfig_t *device,
	char *attr,
	char *name)
{
	char **unavailable;

	/* Get unavailable devices for this device */
	unavailable = devconfig_get_unavailable(device);

	/* Try to add name to array via realloc */
	if ((unavailable = append_to_string_array(unavailable, name)) == NULL) {
	    return (ENOMEM);
	}

	/* Set unavailable devices in the device */
	devconfig_set_unavailable(device, unavailable);

	return (0);
}

/*
 * Validate and set the name attribute in the given hsp devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_hsp_name(
	devconfig_t *hsp,
	char *attr,
	char *name)
{
	return (devconfig_set_hsp_name(hsp, name));
}

/*
 * Validate and set the name attribute in the given disk devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_disk_name(
	devconfig_t *disk,
	char *attr,
	char *name)
{
	return (devconfig_set_name(disk, name));
}

/*
 * Validate and set the name attribute in the given slice devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_slice_name(
	devconfig_t *slice,
	char *attr,
	char *name)
{
	return (devconfig_set_name(slice, name));
}

/*
 * Validate and set the start_block attribute in the given slice
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the start_block
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_slice_start_block(
	devconfig_t *slice,
	char *attr,
	char *value)
{
	long long startsector;

	/* Convert string to long long */
	if (sscanf(value, "%lld", &startsector) != 1) {
	    volume_set_error(gettext("%s: invalid start sector"), value);
	    return (-1);
	}

	/* Set the number of submirrors in the slice */
	return (devconfig_set_slice_start_block(slice, (uint64_t)startsector));
}

/*
 * Validate and set the name attribute in the given volume
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       name
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_volume_name(
	devconfig_t *volume,
	char *attr,
	char *name)
{
	return (devconfig_set_volume_name(volume, name));
}

/*
 * Validate and set the interlace attribute in the given stripe
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the interlace
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_stripe_interlace(
	devconfig_t *stripe,
	char *attr,
	char *value)
{
	int error;
	uint64_t interlace = 0;

	/* Convert interlace string to bytes */
	if ((error = sizestr_to_bytes(
		value, &interlace, interlace_units)) != 0) {
	    return (error);
	}

	/* Set interlace in stripe */
	return (devconfig_set_stripe_interlace(stripe, interlace));
}

/*
 * Validate and set the mincomp attribute in the given stripe
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the mincomp
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_stripe_mincomp(
	devconfig_t *stripe,
	char *attr,
	char *value)
{
	uint16_t mincomp;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &mincomp) != 0) {
	    volume_set_error(
		gettext("invalid minimum stripe components (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_stripe_mincomp(stripe, mincomp));
}

/*
 * Validate and set the maxcomp attribute in the given stripe
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the maxcomp
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_stripe_maxcomp(
	devconfig_t *stripe,
	char *attr,
	char *value)
{
	uint16_t maxcomp;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &maxcomp) != 0) {
	    volume_set_error(
		gettext("invalid maximum stripe components (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_stripe_maxcomp(stripe, maxcomp));
}

/*
 * Validate and set the usehsp attribute in the given volume
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the usehsp
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_volume_usehsp(
	devconfig_t *volume,
	char *attr,
	char *value)
{
	boolean_t usehsp;

	/* Get boolean value */
	if (strtobool(value, &usehsp) != 0) {
	    volume_set_error(
		gettext("%s: invalid boolean value for \"%s\" attribute"),
		value, attr);
	    return (-1);
	}

	/* Set in volume */
	return (devconfig_set_volume_usehsp(volume, usehsp));
}

/*
 * Validate and set the nsubmirrors attribute in the given mirror
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the nsubmirrors
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_mirror_nsubmirrors(
	devconfig_t *mirror,
	char *attr,
	char *value)
{
	uint16_t nsubmirrors;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &nsubmirrors) != 0) {
	    volume_set_error(
		gettext("invalid number of submirrors (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_mirror_nsubs(mirror, nsubmirrors));
}

/*
 * Validate and set the read attribute in the given mirror
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the read
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_mirror_read(
	devconfig_t *mirror,
	char *attr,
	char *value)
{
	mirror_read_strategy_t strategy;

	if (strcmp(value, VALID_MIRROR_READ_ROUNDROBIN) == 0) {
	    strategy = MIRROR_READ_ROUNDROBIN;
	} else

	if (strcmp(value, VALID_MIRROR_READ_GEOMETRIC) == 0) {
	    strategy = MIRROR_READ_GEOMETRIC;
	} else

	if (strcmp(value, VALID_MIRROR_READ_FIRST) == 0) {
	    strategy = MIRROR_READ_FIRST;
	} else

	{
	    volume_set_error(gettext("%s: invalid mirror read value"), value);
	    return (-1);
	}

	return (devconfig_set_mirror_read(mirror, strategy));
}

/*
 * Validate and set the write attribute in the given mirror
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the write
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_mirror_write(
	devconfig_t *mirror,
	char *attr,
	char *value)
{
	mirror_write_strategy_t strategy;

	if (strcmp(value, VALID_MIRROR_WRITE_PARALLEL) == 0) {
	    strategy = MIRROR_WRITE_PARALLEL;
	} else

	if (strcmp(value, VALID_MIRROR_WRITE_SERIAL) == 0) {
	    strategy = MIRROR_WRITE_SERIAL;
	} else

	{
	    volume_set_error(gettext("%s: invalid mirror write value"), value);
	    return (-1);
	}

	return (devconfig_set_mirror_write(mirror, strategy));
}

/*
 * Validate and set the passnum attribute in the given mirror
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the passnum
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_mirror_passnum(
	devconfig_t *mirror,
	char *attr,
	char *value)
{
	uint16_t passnum;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &passnum) != 0) {
	    volume_set_error(
		gettext("invalid mirror pass number (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_mirror_pass(mirror, passnum));
}

/*
 * Validate and set the redundancy attribute in the given volume
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the redundancy
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_volume_redundancy(
	devconfig_t *volume,
	char *attr,
	char *value)
{
	uint16_t redundancy;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &redundancy) != 0) {
	    volume_set_error(
		gettext("invalid redundancy level (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_volume_redundancy_level(volume, redundancy));
}

/*
 * Validate and set the datapaths attribute in the given volume
 * devconfig_t.
 *
 * @param       volume
 *		the devconfig_t in which to set the datapaths
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
validate_set_volume_datapaths(
	devconfig_t *volume,
	char *attr,
	char *value)
{
	uint16_t redundancy;

	/* Convert string to a uint16_t */
	if (str_to_uint16(value, &redundancy) != 0) {
	    volume_set_error(
		gettext("invalid number of data paths (%s): %s"),
		attr, value);
	    return (-1);
	}

	/* Set in stripe */
	return (devconfig_set_volume_npaths(volume, redundancy));
}

/*
 * ******************************************************************
 *
 * XML attribute accessors/converters
 *
 * These functions get a value from the appropriate devconfig_t
 * accessor, and then convert it to a string.
 *
 * ******************************************************************
 */

/*
 * Get, as a string, the value of the name attribute of the given
 * devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the name
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_name(
	devconfig_t *device,
	char *attr,
	char **value)
{
	int error;
	char *name;

	/* Get name */
	if ((error = devconfig_get_name(device, &name)) == 0) {
	    if ((*value = strdup(name)) == NULL) {
		error = ENOMEM;
	    }
	}

	return (error);
}

/*
 * Get, as a string, the value of the passnum attribute of the given
 * mirror devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the passnum
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_mirror_passnum(
	devconfig_t *mirror,
	char *attr,
	char **value)
{
	int error;
	uint16_t passnum;

	/* Get mirror pass number */
	if ((error = devconfig_get_mirror_pass(mirror, &passnum)) == 0) {
	    error = ll_to_str(passnum, value);
	}

	return (error);
}

/*
 * Get, as a string, the value of the read attribute of the given
 * mirror devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the read
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_mirror_read(
	devconfig_t *mirror,
	char *attr,
	char **value)
{
	int error;
	mirror_read_strategy_t read;

	/* Get mirror read strategy */
	if ((error = devconfig_get_mirror_read(mirror, &read)) == 0) {
	    if ((*value = strdup(
		devconfig_read_strategy_to_str(read))) == NULL) {
		error = ENOMEM;
	    }
	}

	return (error);
}

/*
 * Get, as a string, the value of the write attribute of the given
 * mirror devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the write
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_mirror_write(
	devconfig_t *mirror,
	char *attr,
	char **value)
{
	int error;
	mirror_write_strategy_t write;

	/* Get mirror write strategy */
	if ((error = devconfig_get_mirror_write(mirror, &write)) == 0) {
	    if ((*value = strdup(
		devconfig_write_strategy_to_str(write))) == NULL) {
		error = ENOMEM;
	    }
	}

	return (error);
}

/*
 * Get, as a string, the value of the in_blocks attribute of the given
 * device devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the in_blocks
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_size_in_blocks(
	devconfig_t *device,
	char *attr,
	char **value)
{
	int error;
	uint64_t size;

	/* Get size in blocks */
	if ((error = devconfig_get_size_in_blocks(device, &size)) == 0) {
	    error = ll_to_str(size, value);
	}

	return (error);
}

/*
 * Get, as a string, the value of the start_block attribute of the
 * given slice devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the start_block
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_slice_start_block(
	devconfig_t *slice,
	char *attr,
	char **value)
{
	int error;
	uint64_t start;

	/* Get slice start block */
	if ((error = devconfig_get_slice_start_block(slice, &start)) == 0) {
	    error = ll_to_str(start, value);
	}

	return (error);
}

/*
 * Get, as a string, the value of the interlace attribute of the given
 * stripe devconfig_t.  This data must be freed.
 *
 * @param       device
 *		the devconfig_t from which to retrieve the interlace
 *
 * @param       attr
 *		the name of the XML attribute
 *
 * @param       value
 *		RETURN: the value of the XML attribute
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
get_as_string_stripe_interlace(
	devconfig_t *stripe,
	char *attr,
	char **value)
{
	int error;
	uint64_t interlace;

	/* Get interlace */
	if ((error = devconfig_get_stripe_interlace(
		stripe, &interlace)) == 0) {
	    error = bytes_to_sizestr(interlace, value, interlace_units, B_TRUE);
	}

	return (error);
}
