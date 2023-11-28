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
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <thread.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <libxml/debugXML.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xpath.h>
#include <libxml/xmlmemory.h>

#include <pool.h>
#include "pool_internal.h"
#include "pool_impl.h"
#include "pool_xml_impl.h"

/*
 * libpool XML Manipulation Routines
 *
 * pool_xml.c implements the XML manipulation routines used by the libpool
 * XML datastore. The functions are grouped into the following logical areas
 * - Result Sets
 * The XPath API is used to search the XML document represented by a
 * configuration. The results of XPath queries are represented through
 * pool_result_set_t structures as part of the abstraction of the datastore
 * representation. (see pool.c comment for more details)
 *
 * - Property Manipulation
 * Validated XML (XML associated with a DTD) does not allow the introduction
 * of attributes which are not recognised by the DTD. This is a limitation
 * since we want to allow libpool to associate an arbitrary number of
 * properties with an element. The property manipulation code overcomes this
 * limitation by allowing property sub-elements to be created and manipulated
 * through a single API so that they are indistinguishable from attributes
 * to the libpool user.
 *
 * - XML Element/Attribute Manipulation
 * These routines manipulate XML elements and attributes and are the routines
 * which interact most directly with libxml.
 *
 * - File Processing/IO
 * Since libpool must present its data in a consistent fashion, we have to
 * implement file locking above libxml. These routines allow us to lock files
 * during processing and maintain data integrity between processes. Note
 * that locks are at the process scope and are advisory (see fcntl).
 *
 * - Utilities
 * Sundry utility functions that aren't easily categorised.
 */

#define	MAX_PROP_SIZE	1024	/* Size of property buffer */
/*
 * The PAGE_READ_SIZE value is used to determine the size of the input buffer
 * used to parse XML files.
 */
#define	PAGE_READ_SIZE	8192
#define	ELEM_TYPE_COUNT	6	/* Count of Element types */

typedef struct dtype_tbl
{
	xmlChar *dt_name;
	int dt_type;
} dtype_tbl_t;

typedef struct elem_type_tbl
{
	xmlChar *ett_elem;
	dtype_tbl_t (*ett_dtype)[];
} elem_type_tbl_t;

extern int xmlDoValidityCheckingDefaultValue;

/*
 * The _xml_lock is used to lock the state of libpool during
 * xml initialisation operations.
 */
static mutex_t _xml_lock;

const char *element_class_tags[] = {
	"any",
	"system",
	"pool",
	"res_comp",
	"res_agg",
	"comp",
	NULL
};

static const char *data_type_tags[] = {
	"uint",
	"int",
	"float",
	"boolean",
	"string"
};

const char *dtd_location = "file:///usr/share/lib/xml/dtd/rm_pool.dtd.1";

static elem_type_tbl_t elem_tbl[ELEM_TYPE_COUNT] = {0};

/* libpool initialisation indicator */
static int _libpool_xml_initialised = PO_FALSE;

/*
 * Utility functions
 */
/*
 * Those functions which are not static are shared with pool_kernel.c
 * They provide the required XML support for exporting a kernel
 * configuration as an XML document.
 */
void xml_init(void);
static int create_shadow(xmlNodePtr node);
static int pool_xml_free_doc(pool_conf_t *conf);
static int prop_sort(const void *a, const void *b);
static int dtd_exists(const char *path);
static void build_dtype_accelerator(void);
static dtype_tbl_t (*build_dtype_tbl(const xmlChar *rawdata))[];
static int get_fast_dtype(xmlNodePtr node, xmlChar *name);
static int pool_assoc_default_resource_type(pool_t *,
    pool_resource_elem_class_t);

/*
 * XML Data access and navigation APIs
 */
static int pool_build_xpath_buf(pool_xml_connection_t *, const pool_elem_t *,
    pool_elem_class_t, pool_value_t **, char_buf_t *, int);
/*
 * SHARED WITH pool_kernel.c for XML export support
 */
xmlNodePtr node_create(xmlNodePtr parent, const xmlChar *name);
static xmlNodePtr node_create_with_id(xmlNodePtr parent, const xmlChar *name);

/* Configuration */
static int pool_xml_close(pool_conf_t *);
static int pool_xml_validate(const pool_conf_t *, pool_valid_level_t);
static int pool_xml_commit(pool_conf_t *conf);
static int pool_xml_export(const pool_conf_t *conf, const char *location,
    pool_export_format_t fmt);
static int pool_xml_rollback(pool_conf_t *conf);
static pool_result_set_t *pool_xml_exec_query(const pool_conf_t *conf,
    const pool_elem_t *src, const char *src_attr,
    pool_elem_class_t classes, pool_value_t **props);
static int pool_xml_remove(pool_conf_t *conf);
static int pool_xml_res_transfer(pool_resource_t *, pool_resource_t *,
    uint64_t);
static int pool_xml_res_xtransfer(pool_resource_t *, pool_resource_t *,
    pool_component_t **);

/* Connections */
static void pool_xml_connection_free(pool_xml_connection_t *prov);

/* Result Sets */
static pool_xml_result_set_t *pool_xml_result_set_alloc(const pool_conf_t *);
static void pool_xml_result_set_free(pool_xml_result_set_t *rs);
static pool_elem_t *pool_xml_rs_next(pool_result_set_t *set);
static pool_elem_t *pool_xml_rs_prev(pool_result_set_t *set);
static pool_elem_t *pool_xml_rs_first(pool_result_set_t *set);
static pool_elem_t *pool_xml_rs_last(pool_result_set_t *set);
static int pool_xml_rs_set_index(pool_result_set_t *set, int index);
static int pool_xml_rs_get_index(pool_result_set_t *set);
static int pool_xml_rs_count(pool_result_set_t *set);
static int pool_xml_rs_close(pool_result_set_t *set);

/* Element (and sub-type) */
static void pool_xml_elem_init(pool_conf_t *conf, pool_xml_elem_t *elem,
    pool_elem_class_t, pool_resource_elem_class_t, pool_component_elem_class_t);
static int pool_xml_elem_wrap(xmlNodePtr node, pool_elem_class_t class,
    pool_resource_elem_class_t, pool_component_elem_class_t);
static pool_elem_t *pool_xml_elem_create(pool_conf_t *, pool_elem_class_t,
    pool_resource_elem_class_t, pool_component_elem_class_t);
static int pool_xml_elem_remove(pool_elem_t *pe);
static int pool_xml_set_container(pool_elem_t *, pool_elem_t *);
static pool_elem_t *pool_xml_get_container(const pool_elem_t *);

/*
 * Pool element specific
 */
static int pool_xml_pool_associate(pool_t *, const pool_resource_t *);
static int pool_xml_pool_dissociate(pool_t *, const pool_resource_t *);

/*
 * Resource elements specific
 */
static int pool_xml_resource_is_system(const pool_resource_t *);
static int pool_xml_resource_can_associate(const pool_resource_t *);

/* Properties */
static pool_value_class_t pool_xml_get_property(const pool_elem_t *,
    const char *, pool_value_t *);
static int pool_xml_put_property(pool_elem_t *, const char *,
    const pool_value_t *);
static int pool_xml_rm_property(pool_elem_t *, const char *);
static xmlNodePtr property_create(xmlNodePtr, const char *,
    pool_value_class_t);

/* Internal Attribute/Property manipulation */
static int pool_is_xml_attr(xmlDocPtr, const char *, const char *);
static pool_value_class_t pool_xml_get_attr(xmlNodePtr node, xmlChar *name,
    pool_value_t *value);
int pool_xml_set_attr(xmlNodePtr node, xmlChar *name,
    const pool_value_t *value);
static pool_value_class_t pool_xml_get_prop(xmlNodePtr node, xmlChar *name,
    pool_value_t *value);
int pool_xml_set_prop(xmlNodePtr node, xmlChar *name,
    const pool_value_t *value);
static pool_value_t **pool_xml_get_properties(const pool_elem_t *, uint_t *);
/* XML Error handling */
void pool_error_func(void *ctx, const char *msg, ...);

/* XML File Input Processing */
static int pool_xml_open_file(pool_conf_t *conf);
static int pool_xml_parse_document(pool_conf_t *);

/*
 * Initialise this module
 */
void
xml_init()
{
	(void) mutex_lock(&_xml_lock);
	if (_libpool_xml_initialised == PO_TRUE) {
		(void) mutex_unlock(&_xml_lock);
		return;
	}
	xmlInitParser();

	/* Send all XML errors to our debug handler */
	xmlSetGenericErrorFunc(NULL, pool_error_func);
	/* Load up DTD element a-dtype data to improve performance */
	build_dtype_accelerator();
	_libpool_xml_initialised = PO_TRUE;
	(void) mutex_unlock(&_xml_lock);
}

/*
 * Get the next ID for this configuration
 */
static int
get_unique_id(xmlNodePtr node, char *id)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	uint64_t nid = 0;
	if (node->doc->_private) {
		if (pool_get_ns_property(
		    pool_conf_to_elem((pool_conf_t *)node->doc->_private),
		    "_next_id", &val) == POC_UINT)
			(void) pool_value_get_uint64(&val, &nid);
	}
	if (snprintf(id, KEY_BUFFER_SIZE, "id_%llx", nid) > KEY_BUFFER_SIZE) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	pool_value_set_uint64(&val, ++nid);
	return (pool_put_ns_property(
	    pool_conf_to_elem((pool_conf_t *)node->doc->_private), "_next_id",
	    &val));
}

/* Document building functions */

/*
 * node_create() creates a child node of type name of the supplied parent in
 * the supplied document. If the parent or document is NULL, create the node
 * but do not associate it with a parent or document.
 */
xmlNodePtr
node_create(xmlNodePtr parent, const xmlChar *name)
{
	xmlNodePtr node;

	if (parent == NULL)
		node = xmlNewNode(NULL, name);
	else
		node = xmlNewChild(parent, NULL, name, NULL);
	return (node);
}

/*
 * node_create_with_id() creates a child node of type name of the supplied
 * parent with the ref_id generated by get_unique_id(). Actual node creation
 * is performed by node_create() and this function just sets the ref_id
 * property to the value of the id.
 */
static xmlNodePtr
node_create_with_id(xmlNodePtr parent, const xmlChar *name)
{
	char id[KEY_BUFFER_SIZE]; /* Must be big enough for key below */
	xmlNodePtr node = node_create(parent, name);
	if (node != NULL) {
		if (get_unique_id(node, id) != PO_SUCCESS) {
			xmlUnlinkNode(node);
			xmlFreeNode(node); /* recurses all children */
			pool_seterror(POE_DATASTORE);
			return (NULL);
		}
		if (xmlSetProp(node, BAD_CAST c_ref_id, BAD_CAST id) == NULL) {
			xmlUnlinkNode(node);
			xmlFreeNode(node); /* recurses all children */
			pool_seterror(POE_DATASTORE);
			return (NULL);
		}
	}
	return (node);
}

/* Supporting Data Conversion Routines */

/* XML Parser Utility Functions */

/*
 * Handler for XML Errors. Called by libxml at libxml Error.
 */
/*ARGSUSED*/
void
pool_error_func(void *ctx, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	do_dprintf(msg, ap);
	va_end(ap);
}

/*
 * Free the shadowed elements from within the supplied document and then
 * free the document. This function should always be called when freeing
 * a pool document to ensure that all "shadow" resources are reclaimed.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_free_doc(pool_conf_t *conf)
{
	/* Only do any of this if there is a document */
	if (((pool_xml_connection_t *)conf->pc_prov)->pxc_doc != NULL) {
		pool_elem_t *pe;
		pool_result_set_t *rs;
		/* Delete all the "shadowed" children of the doc */
		rs = pool_exec_query(conf, NULL, NULL, PEC_QRY_ANY, NULL);
		if (rs == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
		for (pe = rs->prs_next(rs); pe != NULL; pe = rs->prs_next(rs)) {
			/*
			 * Work out the element type and free the elem
			 */
			free(pe);
		}
		(void) pool_rs_close(rs);
		xmlFreeDoc(((pool_xml_connection_t *)conf->pc_prov)->pxc_doc);
	}
	((pool_xml_connection_t *)conf->pc_prov)->pxc_doc = NULL;
	return (PO_SUCCESS);
}

/*
 * Remove an element from the document. Note that only three types of elements
 * can be removed, res, comp and pools. comp are moved around to the
 * default res when a res is deleted.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_elem_remove(pool_elem_t *pe)
{
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)pe;

	/*
	 * You can only destroy three elements: pools, resources and
	 * components.
	 */
	switch (pe->pe_class) {
	case PEC_POOL:
	case PEC_RES_COMP:
	case PEC_RES_AGG:
	case PEC_COMP:
		if (pxe->pxe_node) {
			xmlUnlinkNode(pxe->pxe_node);
			xmlFreeNode(pxe->pxe_node); /* recurses all children */
		}
		free(pxe);
		break;
	default:
		break;
	}
	return (PO_SUCCESS);
}

/*
 * Create a property element.
 */
static xmlNodePtr
property_create(xmlNodePtr parent, const char *name, pool_value_class_t type)
{

	xmlNodePtr element;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	if ((element = node_create(parent, BAD_CAST "property")) == NULL) {
		pool_seterror(POE_DATASTORE);
		return (NULL);
	}
	if (pool_value_set_string(&val, name) != PO_SUCCESS) {
		xmlFree(element);
		return (NULL);
	}
	(void) pool_xml_set_attr(element, BAD_CAST c_name, &val);
	if (pool_value_set_string(&val, data_type_tags[type]) != PO_SUCCESS) {
		xmlFree(element);
		return (NULL);
	}
	(void) pool_xml_set_attr(element, BAD_CAST c_type, &val);
	return (element);
}

/*
 * External clients need to be able to put/get properties and this is the
 * way to do it.
 * This function is an interceptor, since it will *always* try to manipulate
 * an attribute first. If the attribute doesn't exist, then it will treat
 * the request as a property request.
 */
static pool_value_class_t
pool_xml_get_property(const pool_elem_t *pe, const char *name,
    pool_value_t *val)
{
	pool_value_class_t type;
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)pe;

	/*
	 * "type" is a special attribute which is not visible ever outside of
	 * libpool. Use the specific type accessor function.
	 */
	if (strcmp(name, c_type) == 0) {
		return (pool_xml_get_attr(pxe->pxe_node, BAD_CAST name,
		    val));
	}
	if (is_ns_property(pe, name) != NULL) {	/* in ns */
		if ((type = pool_xml_get_attr(pxe->pxe_node,
		    BAD_CAST property_name_minus_ns(pe, name), val))
		    == POC_INVAL)
			return (pool_xml_get_prop(pxe->pxe_node, BAD_CAST name,
			    val));
	} else
		return (pool_xml_get_prop(pxe->pxe_node, BAD_CAST name, val));

	return (type);
}

/*
 * Put a property on an element. Check if the property is an attribute,
 * if it is update that value. If not add a property element.
 *
 * There are three possible conditions here:
 * - the name is a ns
 *	- the name is an attribute
 *	- the name isn't an attribute
 * - the name is not a ns
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_put_property(pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)pe;

	/*
	 * "type" is a special attribute which is not visible ever outside of
	 * libpool. Use the specific type accessor function.
	 */
	if (strcmp(name, c_type) == 0) {
		return (pool_xml_set_attr(pxe->pxe_node, BAD_CAST name,
		    val));
	}
	if (is_ns_property(pe, name) != NULL) {	/* in ns */
		if (pool_xml_set_attr(pxe->pxe_node,
		    BAD_CAST property_name_minus_ns(pe, name), val) == PO_FAIL)
			return (pool_xml_set_prop(pxe->pxe_node, BAD_CAST name,
			    val));
	} else
		return (pool_xml_set_prop(pxe->pxe_node, BAD_CAST name, val));
	return (PO_SUCCESS);
}

/*
 * Remove a property from an element. Check if the property is an attribute,
 * if it is fail. Otherwise remove the property subelement.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_rm_property(pool_elem_t *pe, const char *name)
{
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)pe;
	xmlXPathContextPtr ctx;
	xmlXPathObjectPtr path;
	char buf[MAX_PROP_SIZE];
	int ret;

	if (xmlHasProp(pxe->pxe_node, BAD_CAST name) != NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/* use xpath to find the node with the appropriate value for name */
	(void) snprintf(buf, sizeof (buf), "property[@name=\"%s\"]", name);
	if ((ctx = xmlXPathNewContext(pxe->pxe_node->doc)) == NULL) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	ctx->node = pxe->pxe_node;
	path = xmlXPathEval(BAD_CAST buf, ctx);

	if (path && (path->type == XPATH_NODESET) &&
	    (path->nodesetval->nodeNr == 1)) {
		xmlUnlinkNode(path->nodesetval->nodeTab[0]);
		xmlFreeNode(path->nodesetval->nodeTab[0]);
		ret = PO_SUCCESS;
	} else {
		pool_seterror(POE_BADPARAM);
		ret = PO_FAIL;
	}
	xmlXPathFreeObject(path);
	xmlXPathFreeContext(ctx);
	return (ret);
}

/*
 * Get the data type for an attribute name from the element node. The data
 * type is returned and the value of the attribute updates the supplied value
 * pointer.
 */
static pool_value_class_t
pool_xml_get_attr(xmlNodePtr node, xmlChar *name, pool_value_t *value)
{
	pool_value_class_t data_type;
	xmlChar *data;
	uint64_t uval;
	int64_t ival;

	if (xmlHasProp(node, name) == NULL && pool_is_xml_attr(node->doc,
	    (const char *) node->name, (const char *) name) == PO_FALSE) {
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}
	if (xmlHasProp(node, BAD_CAST c_a_dtype) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (POC_INVAL);
	}
	data = xmlGetProp(node, name);
	data_type = get_fast_dtype(node, name);
	if (data_type != POC_STRING && data == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (POC_INVAL);
	}
	switch (data_type) {
	case POC_UINT:
		errno = 0;
		uval = strtoull((char *)data, NULL, 0);
		if (errno != 0) {
			data_type =  POC_INVAL;
		}
		else
			pool_value_set_uint64(value, uval);
		break;
	case POC_INT:
		errno = 0;
		ival = strtoll((char *)data, NULL, 0);
		if (errno != 0) {
			data_type =  POC_INVAL;
		}
		else
			pool_value_set_int64(value, ival);
		break;
	case POC_DOUBLE:
		pool_value_set_double(value, atof((const char *)data));
		break;
	case POC_BOOL:
		if (strcmp((const char *)data, "true") == 0)
			pool_value_set_bool(value, PO_TRUE);
		else
			pool_value_set_bool(value, PO_FALSE);
		break;
	case POC_STRING:
		if (pool_value_set_string(value, data ?
		    (const char *)data : "") != PO_SUCCESS) {
			xmlFree(data);
			return (POC_INVAL);
		}
		break;
	case POC_INVAL:
	default:
		break;
	}
	xmlFree(data);
	return (data_type);
}

/*
 * Set the data type for an attribute name from the element node. The
 * supplied value is used to update the designated name using the data
 * type supplied.
 */
int
pool_xml_set_attr(xmlNodePtr node, xmlChar *name, const pool_value_t *value)
{
	xmlChar buf[MAX_PROP_SIZE] = {0};
	uint64_t ures;
	int64_t ires;
	uchar_t bres;
	double dres;
	const char *sres;

	pool_value_class_t data_type;

	if (xmlHasProp(node, name) == NULL && pool_is_xml_attr(node->doc,
	    (const char *) node->name, (const char *) name) == PO_FALSE) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if (xmlHasProp(node, BAD_CAST c_a_dtype) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	data_type = get_fast_dtype(node, name);
	if (data_type != value->pv_class) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	switch (value->pv_class) {
	case POC_UINT:
		(void) pool_value_get_uint64(value, &ures);
		(void) snprintf((char *)buf, sizeof (buf), "%llu",
		    (u_longlong_t)ures);
		break;
	case POC_INT:
		(void) pool_value_get_int64(value, &ires);
		(void) snprintf((char *)buf, sizeof (buf), "%lld",
		    (longlong_t)ires);
		break;
	case POC_DOUBLE:
		(void) pool_value_get_double(value, &dres);
		(void) snprintf((char *)buf, sizeof (buf), "%f", dres);
		break;
	case POC_BOOL:
		(void) pool_value_get_bool(value, &bres);
		if (bres == PO_FALSE)
			(void) snprintf((char *)buf, sizeof (buf),
			    "false");
		else
			(void) snprintf((char *)buf, sizeof (buf),
			    "true");
		break;
	case POC_STRING:
		(void) pool_value_get_string(value, &sres);
		if (sres != NULL)
			(void) snprintf((char *)buf, sizeof (buf), "%s",
			    sres);
		break;
	case POC_INVAL:
	default:
		break;
	}
	if (xmlSetProp(node, name, buf) == NULL) {
		pool_seterror(POE_DATASTORE);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Get the data type for a property name from the element node. The data
 * type is returned and the value of the property updates the supplied value
 * pointer. The user is responsible for freeing the memory associated with
 * a string.
 */
static pool_value_class_t
pool_xml_get_prop(xmlNodePtr node, xmlChar *name, pool_value_t *value)
{
	pool_value_class_t data_type;
	xmlChar *data, *node_data;
	xmlXPathContextPtr ctx;
	xmlXPathObjectPtr path;
	char buf[MAX_PROP_SIZE];
	int64_t uval;
	int64_t ival;

	/* use xpath to find the node with the appropriate value for name */
	(void) snprintf(buf, sizeof (buf), "property[@name=\"%s\"]", name);
	if ((ctx = xmlXPathNewContext(node->doc)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}
	ctx->node = node;
	path = xmlXPathEval(BAD_CAST buf, ctx);

	if (path && (path->type == XPATH_NODESET) &&
	    (path->nodesetval->nodeNr == 1)) {
		int i;
		if (xmlHasProp(path->nodesetval->nodeTab[0],
		    BAD_CAST c_type) == NULL) {
			xmlXPathFreeObject(path);
			xmlXPathFreeContext(ctx);
			pool_seterror(POE_INVALID_CONF);
			return (POC_INVAL);
		}
		/* type is a string representation of the type */
		data = xmlGetProp(path->nodesetval->nodeTab[0],
		    BAD_CAST c_type);
		node_data = xmlNodeGetContent(path->nodesetval->nodeTab[0]);
		data_type = POC_INVAL;
		for (i = 0; i < (sizeof (data_type_tags) /
		    sizeof (data_type_tags[0])); i++) {
			if (strcmp((char *)data, data_type_tags[i]) == 0) {
				data_type = i;
				break;
			}
		}
		switch (data_type) {
		case POC_UINT:
			errno = 0;
			uval = strtoull((char *)node_data, NULL, 0);
			if (errno != 0)
				data_type =  POC_INVAL;
			else
				pool_value_set_uint64(value, uval);
			break;
		case POC_INT:
			errno = 0;
			ival = strtoll((char *)node_data, NULL, 0);
			if (errno != 0)
				data_type =  POC_INVAL;
			else
				pool_value_set_int64(value, ival);
			break;
		case POC_DOUBLE:
			pool_value_set_double(value,
			    atof((const char *)node_data));
			break;
		case POC_BOOL:
			if (strcmp((const char *)node_data, "true")
			    == 0)
				pool_value_set_bool(value, PO_TRUE);
			else
				pool_value_set_bool(value, PO_FALSE);
			break;
		case POC_STRING:
			if (pool_value_set_string(value,
			    (const char *)node_data) != PO_SUCCESS) {
				data_type = POC_INVAL;
				break;
			}
			break;
		case POC_INVAL:
		default:
			break;
		}
		xmlFree(data);
		xmlFree(node_data);
		xmlXPathFreeObject(path);
		xmlXPathFreeContext(ctx);
		return (data_type);
	} else { /* No property exists, clean up and return */
		xmlXPathFreeObject(path);
		xmlXPathFreeContext(ctx);
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}
}

/*
 * Set the data type for a property name from the element node. The
 * supplied value is used to update the designated name using the data
 * type supplied.
 */
int
pool_xml_set_prop(xmlNodePtr node, xmlChar *name, const pool_value_t *value)
{
/* First check if we have a property with this name (and type???). */
	xmlXPathContextPtr ctx;
	xmlXPathObjectPtr path;
	xmlChar buf[MAX_PROP_SIZE];
	xmlNodePtr element;
	uint64_t ures;
	int64_t ires;
	uchar_t bres;
	double dres;
	const char *sres;

	/* use xpath to find the node with the appropriate value for name */
	(void) snprintf((char *)buf, sizeof (buf), "property[@name=\"%s\"]",
	    name);
	if ((ctx = xmlXPathNewContext(node->doc)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	ctx->node = node;
	path = xmlXPathEval(buf, ctx);
	if (path == NULL || path->type != XPATH_NODESET) {
		xmlXPathFreeObject(path);
		xmlXPathFreeContext(ctx);
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	} else {
		if (path->nodesetval->nodeNr == 0)
			element = property_create
			    (node, (const char *)name, value->pv_class);
		else if (path->nodesetval->nodeNr == 1) {
			int i;
			xmlChar *data;

			element = path->nodesetval->nodeTab[0];
			if (xmlHasProp(element, BAD_CAST c_type) == NULL) {
				xmlXPathFreeObject(path);
				xmlXPathFreeContext(ctx);
				pool_seterror(POE_INVALID_CONF);
				return (PO_FAIL);
			}
			data = xmlGetProp(element, BAD_CAST c_type);
			for (i = 0; i < (sizeof (data_type_tags) /
			    sizeof (data_type_tags[0])); i++)
				if (strcmp((char *)data, data_type_tags[i])
				    == 0) {
					break;
				}
			xmlFree(data);
			if (value->pv_class != i) {
				xmlXPathFreeObject(path);
				xmlXPathFreeContext(ctx);
				pool_seterror(POE_BADPARAM);
				return (PO_FAIL);
			}
		} else {
			xmlXPathFreeObject(path);
			xmlXPathFreeContext(ctx);
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
	}

	switch (value->pv_class) {
	case POC_UINT:
		(void) pool_value_get_uint64(value, &ures);
		(void) snprintf((char *)buf, sizeof (buf), "%llu",
		    (u_longlong_t)ures);
		break;
	case POC_INT:
		(void) pool_value_get_int64(value, &ires);
		(void) snprintf((char *)buf, sizeof (buf), "%lld",
		    (longlong_t)ires);
		break;
	case POC_DOUBLE:
		(void) pool_value_get_double(value, &dres);
		(void) snprintf((char *)buf, sizeof (buf), "%f", dres);
		break;
	case POC_BOOL:
		(void) pool_value_get_bool(value, &bres);
		if (bres == PO_FALSE)
			(void) snprintf((char *)buf, sizeof (buf),
			    "false");
		else
			(void) snprintf((char *)buf, sizeof (buf),
			    "true");
		break;
	case POC_STRING:
		(void) pool_value_get_string(value, &sres);
		(void) snprintf((char *)buf, sizeof (buf), "%s", sres);
		break;
	case POC_INVAL:
	default:
		break;
	}
	xmlNodeSetContent(element, buf);
	xmlXPathFreeObject(path);
	xmlXPathFreeContext(ctx);
	return (PO_SUCCESS);
}

/*
 * Return a NULL terminated array of pool_value_t which represents all
 * of the properties stored for an element
 *
 * Return NULL on failure. It is the caller's responsibility to free
 * the returned array of values.
 */
pool_value_t **
pool_xml_get_properties(const pool_elem_t *pe, uint_t *nprops)
{
	pool_value_t **result;
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)pe;
	int i, j;
	pool_conf_t *conf = TO_CONF(pe);
	xmlElementPtr elemDTD;
	xmlAttributePtr attr;
	xmlXPathContextPtr ctx;
	xmlXPathObjectPtr path;
	char_buf_t *cb = NULL;

	*nprops = 0;

	elemDTD = xmlGetDtdElementDesc(pxe->pxe_node->doc->extSubset,
	    pxe->pxe_node->name);
	for (attr = elemDTD->attributes; attr != NULL; attr = attr->nexth) {
		if (strcmp((const char *)attr->name, c_a_dtype) != 0 ||
		    strcmp((const char *)attr->name, c_type) != 0)
			(*nprops)++;
	}
	if ((ctx = xmlXPathNewContext(
	    ((pool_xml_connection_t *)conf->pc_prov)->pxc_doc)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	ctx->node = pxe->pxe_node;
	path = xmlXPathEval(BAD_CAST "property", ctx);

	if (path != NULL && path->type == XPATH_NODESET &&
	    path->nodesetval != NULL)
		(*nprops) += path->nodesetval->nodeNr;

	if ((result = calloc(*nprops + 1, sizeof (pool_value_t *))) == NULL) {
		xmlXPathFreeObject(path);
		xmlXPathFreeContext(ctx);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		xmlXPathFreeObject(path);
		xmlXPathFreeContext(ctx);
		free(result);
		return (NULL);
	}
	/*
	 * Now store our attributes and properties in result
	 */
	for (i = 0, attr = elemDTD->attributes; attr != NULL;
	    attr = attr->nexth, i++) {
		if (strcmp((const char *)attr->name, c_a_dtype) == 0 ||
		    strcmp((const char *)attr->name, c_type) == 0) {
			i--;
			continue;
		}
		result[i] = pool_value_alloc();
		if (pool_xml_get_attr(pxe->pxe_node,
		    BAD_CAST attr->name, result[i]) == POC_INVAL) {
			xmlXPathFreeObject(path);
			xmlXPathFreeContext(ctx);
			while (i-- >= 0)
				pool_value_free(result[i]);
			free(result);
			free_char_buf(cb);
			return (NULL);
		}
		if (strcmp((const char *)attr->name, c_type) != 0) {
			if (set_char_buf(cb, "%s.%s",
			    pool_elem_class_string(pe), attr->name) !=
			    PO_SUCCESS) {
				xmlXPathFreeObject(path);
				xmlXPathFreeContext(ctx);
				while (i-- >= 0)
					pool_value_free(result[i]);
				free(result);
				free_char_buf(cb);
				return (NULL);
			}
			if (pool_value_set_name(result[i], cb->cb_buf) !=
			    PO_SUCCESS) {
				xmlXPathFreeObject(path);
				xmlXPathFreeContext(ctx);
				while (i-- >= 0)
					pool_value_free(result[i]);
				free(result);
				free_char_buf(cb);
				return (NULL);
			}
		} else {
			if (pool_value_set_name(result[i],
			    (const char *)attr->name) != PO_SUCCESS) {
				xmlXPathFreeObject(path);
				xmlXPathFreeContext(ctx);
				while (i-- >= 0)
					pool_value_free(result[i]);
				free(result);
				free_char_buf(cb);
				return (NULL);
			}
		}
	}
	free_char_buf(cb);
	for (j = 0; j < path->nodesetval->nodeNr; j++, i++) {
		xmlChar *name = xmlGetProp(path->nodesetval->nodeTab[j],
		    BAD_CAST c_name);

		result[i] = pool_value_alloc();

		if (pool_xml_get_prop(pxe->pxe_node, name, result[i]) ==
		    POC_INVAL) {
			xmlFree(name);
			xmlXPathFreeObject(path);
			xmlXPathFreeContext(ctx);
			while (i-- >= 0)
				pool_value_free(result[i]);
			free(result);
			return (NULL);
		}
		if (pool_value_set_name(result[i], (const char *)name) !=
		    PO_SUCCESS) {
			xmlFree(name);
			xmlXPathFreeObject(path);
			xmlXPathFreeContext(ctx);
			while (i-- >= 0)
				pool_value_free(result[i]);
			free(result);
			return (NULL);
		}
		xmlFree(name);
	}
	xmlXPathFreeObject(path);
	xmlXPathFreeContext(ctx);
	return (result);
}

/*
 * Store a pointer to one of our data types in the _private member of each
 * XML data node contained within the passed node. Note this function is
 * recursive and so all sub-nodes are also shadowed. Only shadow the nodes
 * which we are interested in, i.e. system, pool, res and comp
 */
static int
create_shadow(xmlNodePtr node)
{
	xmlNodePtr sib;
	int ret = PO_SUCCESS;
	/* Create a data structure of the appropriate type */

	if (0 == (xmlStrcmp(node->name,
	    BAD_CAST element_class_tags[PEC_SYSTEM]))) {
		ret = pool_xml_elem_wrap(node, PEC_SYSTEM, PREC_INVALID,
		    PCEC_INVALID);
	} else if (0 == (xmlStrcmp(node->name,
	    BAD_CAST element_class_tags[PEC_POOL]))) {
		ret = pool_xml_elem_wrap(node, PEC_POOL, PREC_INVALID,
		    PCEC_INVALID);
	} else if (0 == (xmlStrcmp(node->name,
	    BAD_CAST element_class_tags[PEC_RES_COMP]))) {
		xmlChar *data;
		pool_resource_elem_class_t res_class;
		data = xmlGetProp(node, BAD_CAST c_type);

		res_class = pool_resource_elem_class_from_string((char *)data);
		xmlFree(data);
		ret = pool_xml_elem_wrap(node, PEC_RES_COMP, res_class,
		    PCEC_INVALID);
	} else if (0 == (xmlStrcmp(node->name,
	    BAD_CAST element_class_tags[PEC_RES_AGG]))) {
		xmlChar *data;
		pool_resource_elem_class_t res_class;
		data = xmlGetProp(node, BAD_CAST c_type);

		res_class = pool_resource_elem_class_from_string((char *)data);
		xmlFree(data);
		ret = pool_xml_elem_wrap(node, PEC_RES_AGG, res_class,
		    PCEC_INVALID);
	} else if (0 == (xmlStrcmp(node->name,
	    BAD_CAST element_class_tags[PEC_COMP]))) {
		xmlChar *data;
		pool_component_elem_class_t comp_class;
		data = xmlGetProp(node, BAD_CAST c_type);

		comp_class = pool_component_elem_class_from_string(
		    (char *)data);
		xmlFree(data);
		ret = pool_xml_elem_wrap(node, PEC_COMP, PREC_INVALID,
		    comp_class);
	}
	/* Have to shadow all children and all siblings */
	for (sib = node->children; sib != NULL; sib = sib->next) {
		if ((ret = create_shadow(sib)) != PO_SUCCESS)
			break;
	}
	return (ret);
}


/*
 * XML Data access and navigation APIs
 */

/*
 * Close the configuration. There are a few steps to closing a configuration:
 * - Unlock the backing file (if there is one)
 * - Close the file (if there is one)
 * - Free the shadow memory	}Done in pool_xml_free_doc
 * - Free the document		}
 * - Free the data provider for this configuration
 * - Free the configuration location specifier
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_close(pool_conf_t *conf)
{
	pool_xml_connection_t *pxc = (pool_xml_connection_t *)conf->pc_prov;
	int ret = PO_SUCCESS;

	if (pxc->pxc_file != NULL) {
		/* Close (and implicitly) unlock the file */
		if (fclose(pxc->pxc_file) != 0) {
			pool_seterror(POE_SYSTEM);
			ret = PO_FAIL;
		}
		pxc->pxc_file = NULL;
	}
	/* Close the xml specific parts */
	(void) pool_xml_free_doc(conf);
	pool_xml_connection_free((pool_xml_connection_t *)conf->pc_prov);
	return (ret);
}

/*
 * Remove the configuration from the backing store. In XML terms delete
 * the file backing the configuration. You need a copy of the location
 * since the pool_conf_close function, frees the location.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_remove(pool_conf_t *conf)
{
	if (pool_conf_location(conf) != NULL) {
		/* First unlink the file, to prevent races on open */
		if (unlink(pool_conf_location(conf)) != 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		/* Now close the configuration */
		(void) pool_conf_close(conf);
		return (PO_SUCCESS);
	}
	return (PO_FAIL);
}

/*
 * Validate the configuration. There are three levels of validation, loose,
 * strict and runtime. In this, XML, implementation, loose is mapped to XML
 * validation, strict implements additional application level validation
 * checks, e.g. all pools must have unique names, runtime ensures that this
 * configuration would instantiate on the current system.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_validate(const pool_conf_t *conf, pool_valid_level_t level)
{
	pool_xml_connection_t *pxc = (pool_xml_connection_t *)conf->pc_prov;
	xmlValidCtxtPtr cvp;

	if ((cvp = xmlNewValidCtxt()) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	cvp->error    = pool_error_func;
	cvp->warning  = pool_error_func;

	if (xmlValidateDocument(cvp, pxc->pxc_doc) == 0) {
		xmlFreeValidCtxt(cvp);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	xmlFreeValidCtxt(cvp);

	if (level >= POV_RUNTIME) {
		/*
		 * Note: This is resource specific.
		 */
		return (((pool_validate_resource(conf, "pset", c_min_prop, 0) ==
		    PO_SUCCESS) &&
		    (pool_validate_resource(conf, "pset", c_max_prop, 0) ==
		    PO_SUCCESS)) ? PO_SUCCESS : PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Commit the configuration to the backing store. In XML terms this means
 * write the changes to the backing file. Read the comments below for details
 * on exactly how this operation is performed.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_commit(pool_conf_t *conf)
{
	pool_xml_connection_t *prov = (pool_xml_connection_t *)conf->pc_prov;
	xmlOutputBufferPtr buf;

	/*
	 * Ensure that the configuration file has no contents
	 */
	if (fseek(prov->pxc_file, 0, SEEK_SET) != 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if (ftruncate(fileno(prov->pxc_file), 0) == -1) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/*
	 * Create an XML output buffer and write out the contents of the
	 * configuration to the file.
	 */
	if ((buf = xmlOutputBufferCreateFile(prov->pxc_file, NULL)) == NULL) {
		pool_seterror(POE_DATASTORE);
		return (PO_FAIL);
	}

	if (xmlSaveFormatFileTo(buf, prov->pxc_doc, NULL, 1) == -1) {
		pool_seterror(POE_DATASTORE);
		return (PO_FAIL);
	}

	return (PO_SUCCESS);
}

/*
 * Export the configuration in the specified format to the specified location.
 * The only format implemented now is the native format, which saves the
 * active configuration to the supplied location.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_export(const pool_conf_t *conf, const char *location,
    pool_export_format_t fmt)
{
	int ret;

	switch (fmt) {
	case POX_NATIVE:
		ret = xmlSaveFormatFile(location,
		    ((pool_xml_connection_t *)conf->pc_prov)->pxc_doc,
		    1);
		if (ret == -1) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		} else
			return (PO_SUCCESS);

	default:
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
}

/*
 * Discard the configuration and restore the configuration to the values
 * specified in the configuration location.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_rollback(pool_conf_t *conf)
{
	pool_xml_connection_t *prov = (pool_xml_connection_t *)conf->pc_prov;

	/* Rollback the file pointer ready for the reparse */
	if (fseek(prov->pxc_file, 0, SEEK_SET) != 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/* Reparse the document */
	/* In XML terms this means, discard and reparse the document */
	(void) pool_xml_free_doc(conf);
	if (pool_xml_parse_document(conf) == PO_FAIL)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * Allocate a new pool_elem_t in the supplied configuration of the specified
 * class.
 * Returns element pointer/NULL
 */
static void
pool_xml_elem_init(pool_conf_t *conf, pool_xml_elem_t *elem,
    pool_elem_class_t class, pool_resource_elem_class_t res_class,
    pool_component_elem_class_t comp_class)
{
	pool_elem_t *pe = TO_ELEM(elem);
	pe->pe_conf = conf;
	pe->pe_class = class;
	pe->pe_resource_class = res_class;
	pe->pe_component_class = comp_class;
	/* Set up the function pointers for element manipulation */
	pe->pe_get_prop = pool_xml_get_property;
	pe->pe_put_prop = pool_xml_put_property;
	pe->pe_rm_prop = pool_xml_rm_property;
	pe->pe_get_props = pool_xml_get_properties;
	pe->pe_remove = pool_xml_elem_remove;
	pe->pe_get_container = pool_xml_get_container;
	pe->pe_set_container = pool_xml_set_container;
	/*
	 * Specific initialisation for different types of element
	 */
	if (class == PEC_POOL) {
		pool_xml_pool_t *pp = (pool_xml_pool_t *)elem;
		pp->pp_associate = pool_xml_pool_associate;
		pp->pp_dissociate = pool_xml_pool_dissociate;
	}
	if (class == PEC_RES_COMP || class == PEC_RES_AGG) {
		pool_xml_resource_t *pr = (pool_xml_resource_t *)elem;
		pr->pr_is_system = pool_xml_resource_is_system;
		pr->pr_can_associate = pool_xml_resource_can_associate;
	}
}

/*
 * "Wrap" a suplied XML node with a pool_elem_t sub-type of the supplied
 * class.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_elem_wrap(xmlNodePtr node, pool_elem_class_t class,
    pool_resource_elem_class_t res_class,
    pool_component_elem_class_t comp_class)
{
	pool_conf_t *conf = node->doc->_private;
	pool_xml_elem_t *elem;
	/* Need to do some messing about to support SubTypes */
	switch (class) {
	case PEC_SYSTEM:
		if ((elem = malloc(sizeof (pool_xml_system_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_system_t));
		break;
	case PEC_POOL:
		if ((elem = malloc(sizeof (pool_xml_pool_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_pool_t));
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		if ((elem = malloc(sizeof (pool_xml_resource_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_resource_t));
		break;
	case PEC_COMP:
		if ((elem = malloc(sizeof (pool_xml_component_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_component_t));
		break;
	}
	pool_xml_elem_init(conf, elem, class, res_class, comp_class);
	node->_private = elem;
	elem->pxe_node = node;
	return (PO_SUCCESS);
}

/*
 * Associate a pool to the default resource for the supplied resource
 * type.
 */
int
pool_assoc_default_resource_type(pool_t *pool, pool_resource_elem_class_t type)
{
	pool_value_t *props[] = { NULL, NULL, NULL };
	uint_t rl_size;
	pool_resource_t **rsl;
	pool_conf_t *conf = TO_ELEM(pool)->pe_conf;
	char_buf_t *cb = NULL;
	pool_value_t val0 = POOL_VALUE_INITIALIZER;
	pool_value_t val1 = POOL_VALUE_INITIALIZER;

	props[0] = &val0;
	props[1] = &val1;


	if (pool_value_set_string(props[0], pool_resource_type_string(type)) !=
	    PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS) {
		return (PO_FAIL);
	}

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		return (PO_FAIL);
	}

	if (set_char_buf(cb, "%s.default",
	    pool_resource_type_string(type)) !=
	    PO_SUCCESS) {
		free_char_buf(cb);
		return (PO_FAIL);
	}
	if (pool_value_set_name(props[1], cb->cb_buf) != PO_SUCCESS) {
		free_char_buf(cb);
		return (PO_FAIL);
	}
	pool_value_set_bool(props[1], PO_TRUE);
	free_char_buf(cb);

	if ((rsl = pool_query_resources(conf, &rl_size, props)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}

	/*
	 * One default resource set per type
	 */
	if (rl_size != 1) {
		free(rsl);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	if (pool_associate(conf, pool, rsl[0])  < 0) {
		free(rsl);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	free(rsl);
	return (PO_SUCCESS);
}

/*
 * Create an XML node in the supplied configuration with a pool_elem_t
 * sub-type of the supplied class.
 * Returns pool_elem_t pointer/NULL
 */
static pool_elem_t *
pool_xml_elem_create(pool_conf_t *conf, pool_elem_class_t class,
    pool_resource_elem_class_t res_class,
    pool_component_elem_class_t comp_class)
{
	/* In XML terms, create an element of the appropriate class */
	pool_xml_elem_t *elem;
	pool_elem_t *parent;
	pool_system_t *parent_system;

	if (class == PEC_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	/* Now create the XML component and add to it's parent */
	/*
	 * If we know the class of an element, we know it's parent.
	 * PEC_POOL, the parent must be the system node
	 * PEC_RES, treat as pool.
	 * PEC_COMP, we don't know the parent, leave this up to the
	 * create_comp function.
	 */
	/* Since we know the subtype we can create and populate the sub-type */
	switch (class) {
	case PEC_POOL:
		if ((parent_system = pool_conf_system(conf)) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (NULL);
		}
		if ((parent = pool_system_elem(parent_system)) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (NULL);
		}
		if ((elem = malloc(sizeof (pool_xml_system_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_system_t));
		if ((elem->pxe_node = node_create_with_id(
		    ((pool_xml_elem_t *)parent)->pxe_node,
		    BAD_CAST element_class_tags[class])) == NULL) {
			pool_seterror(POE_DATASTORE);
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		if ((parent_system = pool_conf_system(conf)) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (NULL);
		}
		if ((parent = pool_system_elem(parent_system)) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (NULL);
		}
		if ((elem = malloc(sizeof (pool_xml_resource_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_resource_t));
		if ((elem->pxe_node = node_create_with_id
		    (((pool_xml_elem_t *)parent)->pxe_node,
		    BAD_CAST element_class_tags[class])) == NULL) {
			pool_seterror(POE_DATASTORE);
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
		break;
	case PEC_COMP:
		if ((elem = malloc(sizeof (pool_xml_component_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) memset(elem, 0, sizeof (pool_xml_component_t));
		if ((elem->pxe_node = node_create(NULL,
		    BAD_CAST element_class_tags[class])) == NULL) {
			pool_seterror(POE_DATASTORE);
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
		break;
	default:
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	pool_xml_elem_init(conf, elem, class, res_class, comp_class);
	elem->pxe_node->_private = elem;
	if (class == PEC_RES_COMP || class == PEC_RES_AGG ||
	    class == PEC_COMP) {
		/*
		 * Put the type and an invalid sys_id on the node.
		 */
		if (xmlSetProp(elem->pxe_node, BAD_CAST c_sys_prop,
		    BAD_CAST POOL_SYSID_BAD_STRING) == NULL) {
			pool_seterror(POE_DATASTORE);
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
		if (xmlSetProp(elem->pxe_node, BAD_CAST c_type,
		    BAD_CAST pool_elem_class_string(
		    (pool_elem_t *)elem)) == NULL) {
			pool_seterror(POE_DATASTORE);
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
	}
	if (class == PEC_POOL) {
		/*
		 * Note: This is resource specific.
		 */
		if (pool_assoc_default_resource_type(pool_elem_pool(
		    (pool_elem_t *)elem), PREC_PSET) == PO_FAIL) {
			(void) pool_xml_elem_remove((pool_elem_t *)elem);
			return (NULL);
		}
	}
	return ((pool_elem_t *)elem);
}

/*
 * Allocate a data provider for the supplied configuration and optionally
 * discover resources.
 * The data provider is the cross over point from the "abstract" configuration
 * functions into the data representation specific manipulation routines.
 * This function sets up all the required pointers to create an XML aware
 * data provider.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_xml_connection_alloc(pool_conf_t *conf, int oflags)
{
	pool_xml_connection_t *prov;

	xml_init();
	if ((prov = malloc(sizeof (pool_xml_connection_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) memset(prov, 0, sizeof (pool_xml_connection_t));
	/*
	 * Initialise data members
	 */
	prov->pc_name = strdup("LIBXML 2.4.0");
	prov->pc_store_type = XML_DATA_STORE;
	prov->pc_oflags = oflags;
	/*
	 * Initialise function pointers
	 */
	prov->pc_close = pool_xml_close;
	prov->pc_validate = pool_xml_validate;
	prov->pc_commit = pool_xml_commit;
	prov->pc_export = pool_xml_export;
	prov->pc_rollback = pool_xml_rollback;
	prov->pc_exec_query = pool_xml_exec_query;
	prov->pc_elem_create = pool_xml_elem_create;
	prov->pc_remove = pool_xml_remove;
	prov->pc_res_xfer = pool_xml_res_transfer;
	prov->pc_res_xxfer = pool_xml_res_xtransfer;
	/*
	 * End of common initialisation
	 */
	/*
	 * Associate the provider to it's configuration
	 */
	conf->pc_prov = (pool_connection_t *)prov;
	/*
	 * At this point the configuration provider has been initialized,
	 * mark the configuration as valid so that the various routines
	 * which rely on a valid configuration will work correctly.
	 */
	conf->pc_state = POF_VALID;

	if ((oflags & PO_CREAT) != 0) {
		pool_conf_t *dyn;

		if ((dyn = pool_conf_alloc()) == NULL)
			return (PO_FAIL);

		if (pool_conf_open(dyn, pool_dynamic_location(),
		    PO_RDONLY) != PO_SUCCESS) {
			pool_conf_free(dyn);
			return (PO_FAIL);
		}

		if (pool_conf_export(dyn, conf->pc_location,
		    POX_NATIVE) != PO_SUCCESS) {
			(void) pool_conf_close(dyn);
			pool_conf_free(dyn);
			return (PO_FAIL);
		}
		(void) pool_conf_close(dyn);
		pool_conf_free(dyn);
	}

	if (pool_xml_open_file(conf) == PO_FAIL) {
		(void) pool_xml_close(conf);
		return (PO_FAIL);
	}

	return (PO_SUCCESS);
}

/*
 * Free the resources for an XML data provider.
 */
static void
pool_xml_connection_free(pool_xml_connection_t *prov)
{
	free((void *)prov->pc_name);
	free(prov);
}

/*
 * Allocate a result set. The Result Set stores the result of an XPath
 * query along with the parameters used to create the result set (for
 * debugging purposes).
 * Returns pool_xml_result_set_t pointer/NULL
 */
static pool_xml_result_set_t *
pool_xml_result_set_alloc(const pool_conf_t *conf)
{
	pool_xml_result_set_t *rs;

	if ((rs = malloc(sizeof (pool_xml_result_set_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	(void) memset(rs, 0, sizeof (pool_xml_result_set_t));
	rs->prs_conf = conf;
	rs->prs_index = -1;
	rs->prs_active = PO_TRUE;
	/* Fix up the result set accessor functions to the xml specfic ones */
	rs->prs_next = pool_xml_rs_next;
	rs->prs_prev = pool_xml_rs_prev;
	rs->prs_first = pool_xml_rs_first;
	rs->prs_last = pool_xml_rs_last;
	rs->prs_get_index = pool_xml_rs_get_index;
	rs->prs_set_index = pool_xml_rs_set_index;
	rs->prs_close = pool_xml_rs_close;
	rs->prs_count = pool_xml_rs_count;
	return (rs);
}

/*
 * Free a result set. Ensure that the resources are all released at this point.
 */
static void
pool_xml_result_set_free(pool_xml_result_set_t *rs)
{
	if (rs->pxr_path != NULL)
		xmlXPathFreeObject(rs->pxr_path);
	if (rs->pxr_ctx != NULL)
		xmlXPathFreeContext(rs->pxr_ctx);
	free(rs);
}

/*
 * Transfer size from one resource to another.
 * Returns PO_SUCCESS/PO_FAIL
 */
/* ARGSUSED */
int
pool_xml_res_transfer(pool_resource_t *src, pool_resource_t *tgt, uint64_t size)
{
	return (PO_SUCCESS);
}

/*
 * Transfer components rl from one resource to another.
 * Returns PO_SUCCESS/PO_FAIL
 */
/* ARGSUSED */
int
pool_xml_res_xtransfer(pool_resource_t *src, pool_resource_t *tgt,
    pool_component_t **rl) {
	int i;

	/*
	 * Walk the Result Set and move the resource components
	 */
	for (i = 0; rl[i] != NULL; i++) {
		if (pool_set_container(TO_ELEM(tgt), TO_ELEM(rl[i])) ==
		    PO_FAIL) {
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}

/*
 * Return the next element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
static pool_elem_t *
pool_xml_rs_next(pool_result_set_t *set)
{
	pool_elem_t *next;
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	/* Update the context node */
	if (xset->prs_index == xset->pxr_path->nodesetval->nodeNr - 1)
		return (NULL);
	next =
	    xset->pxr_path->nodesetval->nodeTab[++xset->prs_index]->_private;
	return (next);
}

/*
 * Return the previous element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
static pool_elem_t *
pool_xml_rs_prev(pool_result_set_t *set)
{
	pool_elem_t *prev;
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	/* Update the context node */
	if (xset->prs_index < 0)
		return (NULL);
	prev =
	    xset->pxr_path->nodesetval->nodeTab[xset->prs_index--]->_private;
	return (prev);
}

/*
 * Sets the current index in a result set.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_rs_set_index(pool_result_set_t *set, int index)
{
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	if (index < 0 || index >= xset->pxr_path->nodesetval->nodeNr) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	xset->prs_index = index;
	return (PO_SUCCESS);
}

/*
 * Return the current index in a result set.
 * Returns current index
 */
static int
pool_xml_rs_get_index(pool_result_set_t *set)
{
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	return (xset->prs_index);
}

/*
 * Return the first element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
static pool_elem_t *
pool_xml_rs_first(pool_result_set_t *set)
{
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	/* Update the context node */
	return (xset->pxr_path->nodesetval->nodeTab[0]->_private);
}

/*
 * Return the last element in a result set.
 * Returns pool_elem_t pointer/NULL
 */
static pool_elem_t *
pool_xml_rs_last(pool_result_set_t *set)
{
	/* Since I know this is an XML result set */
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	/* Update the context node */
	return (xset->pxr_path->nodesetval->
	    nodeTab[xset->pxr_path->nodesetval->nodeNr-1]->_private);
}

/*
 * Return the number of results in a result set.
 * Returns result count
 */
static int
pool_xml_rs_count(pool_result_set_t *set)
{
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	return (xset->pxr_path->nodesetval->nodeNr);
}


/*
 * Close a result set. Remove this result set from the list of results and
 * free the resources
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_rs_close(pool_result_set_t *set)
{
	pool_xml_result_set_t *xset = (pool_xml_result_set_t *)set;

	pool_xml_result_set_free(xset);
	return (PO_SUCCESS);
}

/*
 * Set the container for a node.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_set_container(pool_elem_t *pp, pool_elem_t *pc)
{
	pool_xml_elem_t *pxp;
	pool_xml_elem_t *pxc;
	xmlNodePtr parent;

	pxp = (pool_xml_elem_t *)pp;
	pxc = (pool_xml_elem_t *)pc;
	parent = pxc->pxe_node->parent;

	xmlUnlinkNode(pxc->pxe_node);
	if (xmlAddChild(pxp->pxe_node, pxc->pxe_node) == NULL) {
		/* Try to move back */
		(void) xmlAddChild(parent, pxc->pxe_node);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	pc->pe_conf = pp->pe_conf;
	return (PO_SUCCESS);
}
/*
 * Get the container for a node.
 * Returns Container/NULL
 */
static pool_elem_t *
pool_xml_get_container(const pool_elem_t *pc)
{
	pool_xml_elem_t *pxc = (pool_xml_elem_t *)pc;

	return ((pool_elem_t *)pxc->pxe_node->parent->_private);
}

/*
 * Note: This function is resource specific, needs extending for other
 * resource types.
 */
int
pool_xml_resource_is_system(const pool_resource_t *pr)
{
	switch (pool_resource_elem_class(TO_ELEM(pr))) {
	case PREC_PSET:
		return (PSID_IS_SYSSET(
		    elem_get_sysid(TO_ELEM(pr))));
	default:
		return (PO_FALSE);
	}
}

/*
 * Note: This function is resource specific, needs extending for other
 * resource types.
 */
int
pool_xml_resource_can_associate(const pool_resource_t *pr)
{
	switch (pool_resource_elem_class(TO_ELEM(pr))) {
	case PREC_PSET:
		return (PO_TRUE);
	default:
		return (PO_FALSE);
	}
}

/*
 * Note: This function is resource specific. It must be extended to support
 * multiple resource types.
 */
int
pool_xml_pool_associate(pool_t *pool, const pool_resource_t *pr)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;

	if (pool_xml_get_property(TO_ELEM(pr),
	    "pset.ref_id", &val) != POC_STRING)
		return (PO_FAIL);
	if (pool_xml_put_property(TO_ELEM(pool), "pool.res", &val) !=
	    PO_SUCCESS)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * pool_xml_pool_dissociate() simply finds the default resource for
 * the type of resource being dissociated and then calls
 * pool_xml_pool_associate() to associate to the default resource.
 */
int
pool_xml_pool_dissociate(pool_t *pool, const pool_resource_t *pr)
{
	const pool_resource_t *default_res;

	if ((default_res = get_default_resource(pr)) == NULL)
		return (PO_FAIL);
	if (default_res == pr)
		return (PO_SUCCESS);
	return (pool_xml_pool_associate(pool, default_res));
}

/*
 * pool_xml_open_file() opens a file for a configuration. This establishes
 * the locks required to ensure data integrity when manipulating a
 * configuration.
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_xml_open_file(pool_conf_t *conf)
{
	struct flock lock;
	struct stat s;

	pool_xml_connection_t *prov = (pool_xml_connection_t *)conf->pc_prov;

	/*
	 * Always close the pxc_file in case there was a previously failed open
	 */
	if (prov->pxc_file != NULL) {
		(void) fclose(prov->pxc_file);
		prov->pxc_file = NULL;
	}

	/*
	 * Check that the DTD required for this operation is present.
	 * If it isn't fail
	 */
	if (dtd_exists(dtd_location) == PO_FALSE) {
		pool_seterror(POE_DATASTORE);
		return (PO_FAIL);
	}

	if ((prov->pc_oflags & PO_RDWR) != 0)
		prov->pxc_file = fopen(conf->pc_location, "r+F");
	else /* Assume opening PO_RDONLY */
		prov->pxc_file = fopen(conf->pc_location, "rF");

	if (prov->pxc_file == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	/*
	 * Setup the lock for the file
	 */
	lock.l_type = (prov->pc_oflags & PO_RDWR) ? F_WRLCK : F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	if (fcntl(fileno(prov->pxc_file), F_SETLKW, &lock) == -1) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/*
	 * Check to see if the document was removed whilst waiting for
	 * the lock. If it was return an error.
	 */
	if (stat(conf->pc_location, &s) == -1) {
		(void) fclose(prov->pxc_file);
		prov->pxc_file = NULL;
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/* Parse the document */
	if (pool_xml_parse_document(conf) != PO_SUCCESS)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * Try to work out if an element contains an attribute of the supplied name.
 * Search the internal subset first and then the external subset.
 * Return PO_TRUE if there is an attribute of that name declared for that
 * element.
 */
int
pool_is_xml_attr(xmlDocPtr doc, const char *elem, const char *attr)
{
	xmlDtdPtr internal = xmlGetIntSubset(doc);
	xmlDtdPtr external = doc->extSubset;

	if (xmlGetDtdAttrDesc(internal, BAD_CAST elem, BAD_CAST attr) == NULL)
		if (xmlGetDtdAttrDesc(external,
		    BAD_CAST elem, BAD_CAST attr) == NULL)
			return (PO_FALSE);
	return (PO_TRUE);
}

/*
 * Execute the specified query using XPath. This complex function relies on
 * a couple of helpers to build up an XPath query, pool_build_xpath_buf in
 * particular.
 * conf - the pool configuration being manipulated
 * src - the root of the search, if NULL that means whole document
 * src_attr - if supplied means an IDREF(S) search on this attribute
 * classes - target classes
 * props - target properties
 * Returns pool_result_set_t pointer/NULL
 */
pool_result_set_t *
pool_xml_exec_query(const pool_conf_t *conf, const pool_elem_t *src,
    const char *src_attr, pool_elem_class_t classes, pool_value_t **props)
{
	char *buf = NULL;
	char_buf_t *cb = NULL;
	pool_xml_result_set_t *rs;
	pool_xml_elem_t *pxe = (pool_xml_elem_t *)src;
	pool_xml_connection_t *prov = (pool_xml_connection_t *)conf->pc_prov;

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
		return (NULL);

	/*
	 * Prior to building up the complex XPath query, check to see if
	 * src_attr is an IDREF(S). If it is use the IDREF(S) information
	 * to generate the query rather than the other data
	 */
	if (src_attr != NULL) {
		char *tok;
		char *lasts;
		char *or = "";
		xmlChar *id;

		/*
		 * Check the arguments for consistency
		 */
		if (pool_is_xml_attr(prov->pxc_doc,
		    element_class_tags[src->pe_class], src_attr) != PO_TRUE) {
			free_char_buf(cb);
			pool_seterror(POE_BADPARAM);
			return (NULL);
		}

		if ((id = xmlGetProp(pxe->pxe_node, BAD_CAST src_attr))
		    == NULL) {
			free_char_buf(cb);
			pool_seterror(POE_DATASTORE);
			return (NULL);
		}
		for (tok = strtok_r((char *)id, "	 ", &lasts);
		    tok != NULL; tok = strtok_r(NULL, "	 ", &lasts)) {
			(void) append_char_buf(cb, "%s//*[@ref_id=\"%s\"]",
			    or, tok);
			or = " | ";
			if ((classes & PEC_QRY_SYSTEM) != 0) {
				if (pool_build_xpath_buf(prov, src, PEC_SYSTEM,
				    props, cb, PO_TRUE) == PO_FAIL) {
					free_char_buf(cb);
					return (NULL);
				}
			}
			if ((classes & PEC_QRY_POOL) != 0) {
				if (pool_build_xpath_buf(prov, src, PEC_POOL,
				    props, cb, PO_TRUE) == PO_FAIL) {
					free_char_buf(cb);
					return (NULL);
				}
			}
			if ((classes & PEC_QRY_RES_COMP) != 0) {
				if (pool_build_xpath_buf(prov, src,
				    PEC_RES_COMP, props, cb, PO_TRUE)
				    == PO_FAIL) {
					free_char_buf(cb);
					return (NULL);
				}
			} else if ((classes & PEC_QRY_RES_AGG) != 0) {
				if (pool_build_xpath_buf(prov, src,
				    PEC_RES_AGG, props, cb, PO_TRUE)
				    == PO_FAIL) {
					free_char_buf(cb);
					return (NULL);
				}
			}
		}
		xmlFree(id);
	} else {
		/*
		 * Build up an XPath query using the supplied parameters.
		 * The basic logic is to:
		 * - Identify which classes are the targets of the query
		 * - For each class work out if the props are attributes or not
		 * - Build up a piece of XPath for each class
		 * - Combine the results into one large XPath query.
		 * - Execute the query.
		 */
		if ((classes & PEC_QRY_SYSTEM) != 0) {
			if (pool_build_xpath_buf(prov, src, PEC_SYSTEM, props,
			    cb, PO_FALSE) == PO_FAIL) {
				free_char_buf(cb);
				return (NULL);
			}
		}
		if ((classes & PEC_QRY_POOL) != 0) {
			if (pool_build_xpath_buf(prov, src, PEC_POOL, props,
			    cb, PO_FALSE) == PO_FAIL) {
				free_char_buf(cb);
				return (NULL);
			}
		}
		if ((classes & PEC_QRY_RES_COMP) != 0) {
			if (pool_build_xpath_buf(prov, src, PEC_RES_COMP, props,
			    cb, PO_FALSE) == PO_FAIL) {
				free_char_buf(cb);
				return (NULL);
			}
		}
		if ((classes & PEC_QRY_RES_AGG) != 0) {
			if (pool_build_xpath_buf(prov, src, PEC_RES_AGG, props,
			    cb, PO_FALSE) == PO_FAIL) {
				free_char_buf(cb);
				return (NULL);
			}
		}
		if ((classes & PEC_QRY_COMP) != 0) {
			if (pool_build_xpath_buf(prov, src, PEC_COMP, props,
			    cb, PO_FALSE) == PO_FAIL) {
				free_char_buf(cb);
				return (NULL);
			}
		}
	}
	buf = strdup(cb->cb_buf);
	free_char_buf(cb);
	/*
	 * Have a buffer at this point, that we can use
	 */
	if ((rs = pool_xml_result_set_alloc(conf)) == NULL) {
		free(buf);
		return (NULL);
	}
	/*
	 * Set up the XPath Query
	 */
	if ((rs->pxr_ctx = xmlXPathNewContext(
	    ((pool_xml_connection_t *)conf->pc_prov)->pxc_doc)) == NULL) {
		free(buf);
		(void) pool_xml_rs_close((pool_result_set_t *)rs);
		pool_seterror(POE_DATASTORE);
		return (NULL);
	}
	if (src == NULL)
		rs->pxr_ctx->node = xmlDocGetRootElement
		    (((pool_xml_connection_t *)conf->pc_prov)->pxc_doc);
	else
		rs->pxr_ctx->node = pxe->pxe_node;
	/*
	 * Select
	 */
	rs->pxr_path = xmlXPathEval(BAD_CAST buf, rs->pxr_ctx);
	free(buf);
	/*
	 * Generate the result set and wrap the results as pool_elem_t
	 */
	if (rs->pxr_path->nodesetval->nodeNr == 0)
		pool_seterror(POE_INVALID_SEARCH);
	return ((pool_result_set_t *)rs);
}

/*
 * Build an XPath query buffer. This is complex and a little fragile, but
 * I'm trying to accomplish something complex with as little code as possible.
 * I wait the implementation of XMLQuery with baited breath...
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
pool_build_xpath_buf(pool_xml_connection_t *prov, const pool_elem_t *src,
    pool_elem_class_t class, pool_value_t *props[], char_buf_t *cb, int is_ref)
{
	int i;
	const char *ATTR_FMTS[] = {
		"[ @%s=\"%llu\" ]",	/* POC_UINT */
		"[ @%s=\"%lld\" ]",	/* POC_INT */
		"[ @%s=\"%f\" ]",	/* POC_DOUBLE */
		"[ @%s=\"%s\" ]",	/* POC_BOOL */
		"[ @%s=\"%s\" ]",	/* POC_STRING */
	};
	const char *PROP_FMTS[] = {
		"[ property[@name=\"%s\"][text()=\"%llu\"] ]",	/* POC_UINT */
		"[ property[@name=\"%s\"][text()=\"%lld\"] ]",	/* POC_INT */
		"[ property[@name=\"%s\"][text()=\"%f\"] ]",	/* POC_DOUBLE */
		"[ property[@name=\"%s\"][text()=\"%s\"] ]",	/* POC_BOOL */
		"[ property[@name=\"%s\"][text()=\"%s\"] ]"	/* POC_STRING */
	};
	const char **fmts;
	int nprop;
	const char *last_prop_name = NULL;
	char *type_prefix = NULL;
	int has_type = PO_FALSE;

	if (is_ref == PO_FALSE) {
		if (cb->cb_buf != NULL && strlen(cb->cb_buf) > 0)
			(void) append_char_buf(cb, " |");
		if (src != NULL)
			(void) append_char_buf(cb, " ./");
		else
			(void) append_char_buf(cb, "//");
		(void) append_char_buf(cb, element_class_tags[class]);
	}
	if (props == NULL || props[0] == NULL)
		return (PO_SUCCESS);
	for (nprop = 0; props[nprop] != NULL; nprop++)
		/* Count properties */;
	/*
	 * Sort the attributes and properties by name.
	 */
	qsort(props, nprop, sizeof (pool_value_t *), prop_sort);
	for (i = 0; i < nprop; i++) {
		int is_attr = 0;
		const char *prefix;
		const char *prop_name;
		uint64_t uval;
		int64_t ival;
		double dval;
		uchar_t bval;
		const char *sval;
		pool_value_class_t pvc;

		prop_name = pool_value_get_name(props[i]);
		if ((prefix = is_a_known_prefix(class, prop_name)) != NULL) {
			const char *attr_name;
			/*
			 * Possibly an attribute. Strip off the prefix.
			 */
			if (strcmp(prop_name, c_type) == 0) {
				has_type = PO_TRUE;
				attr_name = prop_name;
			} else
				attr_name = prop_name + strlen(prefix) + 1;
			if (pool_is_xml_attr(prov->pxc_doc,
			    element_class_tags[class], attr_name)) {
				is_attr = 1;
				prop_name = attr_name;
				if (class == PEC_RES_COMP ||
				    class == PEC_RES_AGG ||
				    class == PEC_COMP) {
					if (type_prefix != NULL)
						free(type_prefix);
					type_prefix = strdup(prefix);
				}
			}
		}
		if (is_attr)  {
			fmts = ATTR_FMTS;
		} else {
			fmts = PROP_FMTS;
		}
		/*
		 * Add attributes/properties to the search buffer
		 */
		switch ((pvc = pool_value_get_type(props[i]))) {
		case POC_UINT:
			(void) pool_value_get_uint64(props[i], &uval);
			if (append_char_buf(cb, fmts[pvc], prop_name, uval)
			    == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
			break;
		case POC_INT:
			(void) pool_value_get_int64(props[i], &ival);
			if (append_char_buf(cb, fmts[pvc], prop_name, ival)
			    == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
			break;
		case POC_DOUBLE:
			(void) pool_value_get_double(props[i], &dval);
			if (append_char_buf(cb, fmts[pvc], prop_name, dval)
			    == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
			break;
		case POC_BOOL:
			(void) pool_value_get_bool(props[i], &bval);
			if (append_char_buf(cb, fmts[pvc], prop_name,
			    bval ? "true" : "false") == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
			break;
		case POC_STRING:
			(void) pool_value_get_string(props[i], &sval);
			if (append_char_buf(cb, fmts[pvc], prop_name, sval)
			    == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
			break;
		default:
			free(type_prefix);
			pool_seterror(POE_INVALID_SEARCH);
			return (PO_FAIL);
		}
		if (last_prop_name != NULL) {
			const char *suffix1, *suffix2;
			/*
			 * Extra fiddling for namespaces
			 */
			suffix1 = strrchr(prop_name, '.');
			suffix2 = strrchr(last_prop_name, '.');

			if (suffix1 != NULL || suffix2 != NULL) {
				if (suffix1 == NULL)
					suffix1 = prop_name;
				else
					suffix1++;
				if (suffix2 == NULL)
					suffix2 = last_prop_name;
				else
					suffix2++;
			} else {
				suffix1 = prop_name;
				suffix2 = last_prop_name;
			}
			if (strcmp(suffix1, suffix2) == 0) {
				char *where = strrchr(cb->cb_buf, '[');
				if (is_attr != PO_TRUE) {
					/* repeat */
					while (*--where != '[')
						;
					while (*--where != '[')
						;
				}
				*(where - 1) = 'o';
				*where = 'r';
			}
		}
		last_prop_name = prop_name;
	}
	if (has_type == PO_FALSE) {
		if (type_prefix) {
			if (append_char_buf(cb, ATTR_FMTS[POC_STRING],
			    c_type, type_prefix) == PO_FAIL) {
				free(type_prefix);
				return (PO_FAIL);
			}
		}
	}
	free(type_prefix);
	return (PO_SUCCESS);
}

/*
 * Utility routine for use by quicksort. Assumes that the supplied data
 * are pool values and compares the names of the two pool values.
 * Returns an integer greater than, equal to, or less than 0.
 */
static int
prop_sort(const void *a, const void *b)
{
	pool_value_t **prop_a = (pool_value_t **)a;
	pool_value_t **prop_b = (pool_value_t **)b;
	const char *str_a;
	const char *str_b;
	const char *suffix1, *suffix2;

	str_a = pool_value_get_name(*prop_a);
	str_b = pool_value_get_name(*prop_b);
	/*
	 * Extra fiddling for namespaces
	 */
	suffix1 = strrchr(str_a, '.');
	suffix2 = strrchr(str_b, '.');

	if (suffix1 != NULL || suffix2 != NULL) {
		if (suffix1 == NULL)
			suffix1 = str_a;
		else
			suffix1++;
		if (suffix2 == NULL)
			suffix2 = str_b;
		else
			suffix2++;
	} else {
		suffix1 = str_a;
		suffix2 = str_b;
	}
	return (strcmp(suffix1, suffix2));
}

/*
 * Order the elements by (ref_id)
 */

/*
 * Returns PO_TRUE/PO_FALSE to indicate whether the supplied path exists on the
 * system. It is assumed that the supplied path is in URL format and represents
 * a file and so file:// is stripped from the start of the search.
 */
static int
dtd_exists(const char *path)
{
	struct stat buf;

	if (strstr(path, "file://") != path)
		return (PO_FALSE);

	if (path[7] == 0)
		return (PO_FALSE);

	if (stat(&path[7], &buf) == 0)
		return (PO_TRUE);
	return (PO_FALSE);
}

/*
 * Build the dtype structures to accelerate data type lookup operations. The
 * purpose is to avoid expensive XML manipulations on data which will not
 * change over the life of a library invocation. It is designed to be invoked
 * once from the library init function.
 */
static void
build_dtype_accelerator(void)
{
	xmlDtdPtr dtd;
	const xmlChar *elem_list[ELEM_TYPE_COUNT] = {
		BAD_CAST "res_comp",
		BAD_CAST "res_agg",
		BAD_CAST "comp",
		BAD_CAST "pool",
		BAD_CAST "property",
		BAD_CAST "system" };
	int i;

	if (_libpool_xml_initialised == PO_TRUE)
		return;

	/* Load up the d-type data for each element */
	/*
	 * Store data type information in nested lists
	 * Top level list contains attribute declaration pointers which
	 * can be used to match with supplied nodes.
	 * Second level list contains attribute type information for each
	 * element declaration
	 */
	/*
	 * Unfortunately, there's no easy way to get a list of all DTD
	 * element descriptions as there is no libxml API to do this (they
	 * are stored in a hash, which I guess is why). Explicitly seek
	 * for descriptions for elements that are known to hold an a-dtype
	 * attribute and build accelerators for those elements.
	 * If the DTD changes, the library may have to change as well now,
	 * since this code makes explicit assumptions about which elements
	 * contain a-dtype information.
	 */

	if ((dtd = xmlParseDTD(BAD_CAST "-//Sun Microsystems Inc//DTD Resource"
	    " Management All//EN", BAD_CAST dtd_location)) == NULL)
		return;
	for (i = 0; i < ELEM_TYPE_COUNT; i++) {
		xmlElementPtr elem;
		xmlAttributePtr attr;

		if ((elem = xmlGetDtdElementDesc(dtd, elem_list[i])) == NULL)
			return;
		elem_tbl[i].ett_elem = xmlStrdup(elem->name);
		/* Walk the list of attributes looking for a-dtype */
		for (attr = elem->attributes; attr != NULL;
		    attr = attr->nexth) {
			if (strcmp((const char *)attr->name, c_a_dtype) == 0) {
				/*
				 * Allocate a dtype_tbl_t
				 */
				elem_tbl[i].ett_dtype =
				    build_dtype_tbl(attr->defaultValue);
				/* This could have returned NULL */
			}
		}
	}
	xmlFreeDtd(dtd);
}

/*
 * build_dtype_tbl() parses the supplied data and returns an array (max size
 * of 10, increase if required) of dtype_tbl_t structures holding data type
 * information for an element. The supplied data is assumed to be in "a-dtype"
 * format. The dtype_tbl_t array is NULL terminated, which is why space for
 * 11 members is allocated.
 */
static dtype_tbl_t
(*build_dtype_tbl(const xmlChar *rawdata))[]
{
	char *tok;
	char *lasts;
	dtype_tbl_t (*tbl)[];
	int j = 0;
	xmlChar *data;
	const int max_attr = 11; /* Not more than 10 types per element */

	/*
	 * Parse the supplied data, assumed to be in a-dtype format, and
	 * generate a lookup table which is indexed by the name and contains
	 * the data type
	 */
	if (rawdata == NULL)
	return (NULL);
	if ((data = xmlStrdup(rawdata)) == NULL)
	return (NULL);
	if ((tbl = calloc(max_attr, sizeof (dtype_tbl_t))) == NULL) {
		xmlFree(data);
		return (NULL);
	}
	for (tok = strtok_r((char *)data, "	 ", &lasts); tok != NULL;
	    tok = strtok_r(NULL, "	 ", &lasts)) {
		    int i;
		    (*tbl)[j].dt_name  = xmlStrdup(BAD_CAST tok);
		    if ((tok = strtok_r(NULL, "	 ", &lasts)) == NULL) {
			    int k = j;
			    for (j = 0; j < k; j++)
				    free((*tbl)[j].dt_name);
			    pool_seterror(POE_DATASTORE);
			    xmlFree(data);
			    free(tbl);
			    return (NULL);
		    }
		    for (i = 0; i < (sizeof (data_type_tags) /
			sizeof (data_type_tags[0])); i++) {
				if (strcmp(tok, data_type_tags[i]) == 0)
				(*tbl)[j++].dt_type = i;
			}
		    if (j == max_attr) { /* too many attributes, bail out */
			    for (j = 0; j < max_attr; j++)
			    free((*tbl)[j].dt_name);
			    free(tbl);
			    xmlFree(data);
			    return (NULL);
		    }
	    }
	(*tbl)[j].dt_name = NULL; /* Terminate the table */
	xmlFree(data);
	return (tbl);
}

/*
 * get_fast_dtype() finds the data type for a supplied attribute name on a
 * supplied node. This is called get_fast_dtype() because it uses the cached
 * data type information created at library initialisation.
 */
static int
get_fast_dtype(xmlNodePtr node, xmlChar *name)
{
	int i;
	xmlElementPtr elem;

	if ((elem = xmlGetDtdElementDesc(node->doc->extSubset, node->name))
	    == NULL) {
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}

	for (i = 0; i < ELEM_TYPE_COUNT; i++) {
		if (xmlStrcmp(elem_tbl[i].ett_elem, elem->name) == 0) {
			dtype_tbl_t (*tbl)[] = elem_tbl[i].ett_dtype;
			int j = 0;

			if (tbl == NULL)
				break;
			for (j = 0; (*tbl)[j].dt_name != NULL; j++)
				if (xmlStrcmp(name, (*tbl)[j].dt_name) == 0)
					return ((*tbl)[j].dt_type); /* found */
			break; /* if we didn't find it in the elem, break */
		}
	}
	/* If we can't find it, say it's a string */
	return (POC_STRING);
}

/*
 * pool_xml_parse_document() parses the file associated with a supplied
 * configuration to regenerate the runtime representation. The supplied
 * configuration must reference an already opened file and this is used
 * to generate the XML representation via the configuration provider's
 * pxc_doc member.
 * size must be >=4 in order for "content encoding detection" to work.
 */
static int
pool_xml_parse_document(pool_conf_t *conf)
{
	int res;
	char chars[PAGE_READ_SIZE];
	struct stat f_stat;
	xmlParserCtxtPtr ctxt;
	size_t size;
	pool_xml_connection_t *prov = (pool_xml_connection_t *)conf->pc_prov;
	xmlNodePtr root;
	pool_resource_t **rsl;
	uint_t nelem;
	int i;

	if (fstat(fileno(prov->pxc_file), &f_stat) == -1) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if (f_stat.st_size == 0) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	} else
		size = f_stat.st_size < 4 ? 4 : PAGE_READ_SIZE;

	res = fread(chars, 1, size, prov->pxc_file);

	if (res >= 4) {
		xmlValidCtxtPtr cvp;

		if ((ctxt = xmlCreatePushParserCtxt(NULL, NULL,
		    chars, res, conf->pc_location)) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}

		xmlCtxtUseOptions(ctxt,
		    XML_PARSE_DTDLOAD | XML_PARSE_DTDVALID |
		    XML_PARSE_NOBLANKS);

		while ((res = fread(chars, 1, size, prov->pxc_file)) > 0) {
			if (xmlParseChunk(ctxt, chars, res, 0) != 0) {
				xmlFreeParserCtxt(ctxt);
				pool_seterror(POE_INVALID_CONF);
				return (PO_FAIL);
			}
		}
		if (xmlParseChunk(ctxt, chars, 0, 1) != 0) {
			xmlFreeParserCtxt(ctxt);
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}

		if ((cvp = xmlNewValidCtxt()) == NULL) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
		cvp->error    = pool_error_func;
		cvp->warning  = pool_error_func;

		if (xmlValidateDocument(cvp, ctxt->myDoc) == 0) {
			xmlFreeValidCtxt(cvp);
			xmlFreeParserCtxt(ctxt);
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
		prov->pxc_doc = ctxt->myDoc;
		xmlFreeValidCtxt(cvp);
		xmlFreeParserCtxt(ctxt);
	}
	if (prov->pxc_doc == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	prov->pxc_doc->_private = conf;

	/* Get the root element */
	if ((root = xmlDocGetRootElement(prov->pxc_doc)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	/*
	 * Ensure that the parsed tree has been contained within
	 * our shadow tree.
	 */
	if (create_shadow(root) != PO_SUCCESS) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}

	if (pool_xml_validate(conf, POV_STRICT) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	/*
	 * For backwards compatibility with S9, make sure that all
	 * resources have a size and that it is correct.
	 */
	if ((rsl = pool_query_resources(conf, &nelem, NULL)) != NULL) {
		pool_value_t val = POOL_VALUE_INITIALIZER;
		for (i = 0; i < nelem; i++) {
			if (pool_get_ns_property(TO_ELEM(rsl[i]), c_size_prop,
			    &val) != POC_UINT) {
				pool_component_t **cs;
				uint_t size;
				if ((cs = pool_query_resource_components(conf,
				    rsl[i], &size, NULL)) != NULL) {
					free(cs);
					pool_value_set_uint64(&val, size);
				} else
					pool_value_set_uint64(&val, 0);
				if (pool_put_any_ns_property(TO_ELEM(rsl[i]),
				    c_size_prop, &val)  != PO_SUCCESS) {
					free(rsl);
					return (PO_FAIL);
				}
			}
		}
		free(rsl);
	}
	return (PO_SUCCESS);
}
