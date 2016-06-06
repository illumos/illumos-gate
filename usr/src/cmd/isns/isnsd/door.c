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

#include    <libxml/xmlreader.h>
#include    <libxml/xmlwriter.h>
#include    <libxml/tree.h>
#include    <libxml/parser.h>
#include    <libxml/xpath.h>
#include    <stropts.h>
#include    <door.h>
#include    <errno.h>
#include    <sys/types.h>
#include    <unistd.h>
#include    <pwd.h>
#include    <auth_attr.h>
#include    <secdb.h>
#include    <sys/stat.h>
#include    <fcntl.h>
#include    <sys/stat.h>
#include    <sys/mman.h>
#include    <string.h>
#include    <alloca.h>
#include    <pthread.h>
#include    <ucred.h>
#include    "isns_server.h"
#include    "admintf.h"
#include    "isns_mgmt.h"
#include    "isns_utils.h"
#include    "isns_protocol.h"
#include    "isns_log.h"
#include    "isns_provider.h"

/* door creation flag */
extern boolean_t door_created;

/* macro for allocating name buffers for the request */
#define	NEW_REQARGV(old, n) (xmlChar **)realloc((xmlChar *)old, \
	(unsigned)(n+2) * sizeof (xmlChar *))

/* macro for allocating association pair buffers for the request */
#define	NEW_REQPAIRARGV(old, n) (assoc_pair_t **)realloc((assoc_pair_t *)old, \
	(unsigned)(n+2) * sizeof (assoc_pair_t *))

/* macro for allocating DD/DD set attribute list buffers for the request */
#define	NEW_REQATTRLISTARGV(old, n)\
	(object_attrlist_t **)realloc((object_attrlist_t *)old, \
	(unsigned)(n+2) * sizeof (object_attrlist_t *))

#if LIBXML_VERSION >= 20904
#define	XMLSTRING_CAST (const char *)
#else
#define	XMLSTRING_CAST (const xmlChar *)
#endif

/* operation table */
static op_table_entry_t op_table[] = {
	{GET, get_op},
	{GETASSOCIATED, getAssociated_op},
	{ENUMERATE, enumerate_op},
	{CREATEMODIFY, createModify_op},
	{DELETE, delete_op},
	{NULL, 0}
};

/* object table */
static obj_table_entry_t obj_table[] = {
	{NODEOBJECT, Node},
	{DDOBJECT, DiscoveryDomain},
	{DDSETOBJECT, DiscoveryDomainSet},
	{DDOBJECTMEMBER, DiscoveryDomainMember},
	{DDSETOBJECTMEMBER, DiscoveryDomainSetMember},
	{ISNSSERVER, ServerConfig},
	{NULL, 0}
};

/*
 * list to capture thread id and associated door return buffer
 * the return buffer from the previous door return is freed
 * when the same thread is invoked to take another request.
 * While the server is running one buffer is outstanding
 * to be freed.
 */
static thr_elem_t *thr_list = NULL;

/*
 * get_op_id_from_doc --
 *	    extracts an operation id through the given context ptr.
 *
 * ctext: context ptr for the original doc
 *
 * Returns an operation id if found or -1 otherwise.
 */
static int
get_op_id_from_doc(xmlXPathContextPtr ctext)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	int i;

	for (i = 0; op_table[i].op_str != NULL; i++) {
	    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
		op_table[i].op_str);
	    xpath_obj = xmlXPathEvalExpression(expr, ctext);
	    if ((xpath_obj) && (xpath_obj->nodesetval) &&
		(xpath_obj->nodesetval->nodeNr > 0) &&
		(xpath_obj->nodesetval->nodeTab)) {
		isnslog(LOG_DEBUG, "get_op_id_from_doc ",
		"xpath obj->nodesetval->nodeNr: %d",
		xpath_obj->nodesetval->nodeNr);
		isnslog(LOG_DEBUG, "get_op_id_from_doc", "operation: %s id: %d",
		    op_table[i].op_str, op_table[i].op_id);
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		return (op_table[i].op_id);
	    }
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	return (-1);
}

/*
 * process_get_request_from_doc --
 *	    looks for the object through the context ptr and gets the object
 *	    name.  Possible object types are Node, DD, DD set and server-config.
 *
 * ctext: context ptr for the original doc to parse request info.
 * req: request to be filled up.
 *
 * Returns 0 if successful or an error code otherwise.
 */
static int
process_get_request_from_doc(xmlXPathContextPtr ctext, request_t *req)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	xmlNodeSetPtr r_nodes = NULL;
	xmlAttrPtr attr = NULL;
	int i, cnt;

	int obj = 0;

	isnslog(LOG_DEBUG, "process_get_request_from_doc", "entered");
	(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
	    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", ISNSOBJECT);
	xpath_obj = xmlXPathEvalExpression(expr, ctext);
	if ((xpath_obj) && (xpath_obj->nodesetval) &&
	    (xpath_obj->nodesetval->nodeTab) &&
	    (xpath_obj->nodesetval->nodeNr > 0) &&
	    (xpath_obj->nodesetval->nodeTab[0]->children) &&
	    (xpath_obj->nodesetval->nodeTab[0]->children->name)) {
	    for (i = 0; obj_table[i].obj_str != NULL; i++) {
		/*
		 * To handle DiscoveryDomain and DiscoveryDomainSet
		 * searches isnsobject instead of the object directly.
		 */
		if (xmlStrncmp(
		    xpath_obj->nodesetval->nodeTab[0]->children->name,
		    (xmlChar *)obj_table[i].obj_str, xmlStrlen(
		    xpath_obj->nodesetval->nodeTab[0]->children->name))
		    == 0) {
			obj = obj_table[i].obj_id;
			break;
		}
	    }
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	}

	if (obj == 0) {
	    /* check the server config request. */
	    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
	    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", ISNSSERVER);
	    xpath_obj = xmlXPathEvalExpression(expr, ctext);
	    if ((xpath_obj) && (xpath_obj->nodesetval) &&
		(xpath_obj->nodesetval->nodeNr > 0) &&
		(xpath_obj->nodesetval->nodeTab)) {
		for (i = 0; obj_table[i].obj_str != NULL; i++) {
		    if (strncmp(ISNSSERVER, obj_table[i].obj_str,
			strlen(ISNSSERVER)) == 0) {
			obj = obj_table[i].obj_id;
			break;
		    }
		}
	    }
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	}

	if (obj == 0) {
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	req->op_info.obj = obj;

	if (ISNS_MGMT_OBJECT_TYPE_ENABLED()) {
	    ISNS_MGMT_OBJECT_TYPE(obj);
	}

	(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 12,
	    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
	    obj_table[i].obj_str);
	xpath_obj = xmlXPathEvalExpression(expr, ctext);
	if (((xpath_obj == NULL) || (xpath_obj->nodesetval == NULL) ||
	    (xpath_obj->nodesetval->nodeNr <= 0) ||
	    (xpath_obj->nodesetval->nodeTab == NULL))) {
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	switch (obj) {
	    /* using the same algorithm for isns object */
	    case Node:
	    case DiscoveryDomain:
	    case DiscoveryDomainSet:
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.data = (xmlChar **) malloc(sizeof (xmlChar *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)NAMEATTR,
			    xmlStrlen((xmlChar *)NAMEATTR)) == 0) {
				req->req_data.data =
				    NEW_REQARGV(req->req_data.data, req->count);
				if (req->req_data.data == (xmlChar **)NULL) {
				    if (xpath_obj)
					xmlXPathFreeObject(xpath_obj);
				    return (ERR_MALLOC_FAILED);
				}
				req->req_data.data[req->count] =
				    xmlNodeGetContent(attr->children);
				req->req_data.data[++req->count] = NULL;
			}
		    }
		}
		break;
	    case ServerConfig:
		/* indication the obj type is sufficient. */
		break;
	    default:
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		return (ERR_XML_OP_FAILED);
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	return (0);
}

/*
 * process_enumerate_request_from_doc --
 *	    looks for the object through the context ptr and sets the
 *	    request with object type.
 *
 * ctext: context ptr for the original doc to parse request info.
 * req: request to be filled up.
 *
 * Returns 0 if successful or an error code otherwise.
 */
static int
process_enumerate_request_from_doc(xmlXPathContextPtr ctext, request_t *req)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	int i;

	int obj = 0;

	isnslog(LOG_DEBUG, "process_enumerate_request_from_doc", "entered");
	(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
	    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", ISNSOBJECTTYPE);
	xpath_obj = xmlXPathEvalExpression(expr, ctext);
	isnslog(LOG_DEBUG, "process_enumerate_request_from_doc",
	"xpath obj->nodesetval->nodeNR: %d", xpath_obj->nodesetval->nodeNr);
	if ((xpath_obj) && (xpath_obj->nodesetval) &&
	    (xpath_obj->nodesetval->nodeNr > 0) &&
	    (xpath_obj->nodesetval->nodeTab)) {
	    for (i = 0; obj_table[i].obj_str != NULL; i++) {
		if (xmlStrncmp(
		    xpath_obj->nodesetval->nodeTab[0]->children->content,
		    (xmlChar *)obj_table[i].obj_str, xmlStrlen((xmlChar *)
		    xpath_obj->nodesetval->nodeTab[0]->children->content))
		    == 0) {
		    obj = obj_table[i].obj_id;
		    break;
		}
	    }
	} else {
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);

	if (obj == 0) {
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	req->op_info.obj = obj;

	if (ISNS_MGMT_OBJECT_TYPE_ENABLED()) {
	    ISNS_MGMT_OBJECT_TYPE(obj);
	}

	return (0);
}

/*
 * process_getAssociated_request_from_doc --
 *	    first looks for association type through the contexti and then
 *	    find out the given object.  That will indicate the direction of
 *	    association, containter to member or vice versa.
 *	    Lastly it extract the object name form the doc that assocation
 *	    is requested.
 *
 * ctext: context ptr for the original doc to parse request info.
 * req: request to be filled up.
 *
 * Returns 0 if successful or an error code otherwise.
 */
static int
process_getAssociated_request_from_doc(xmlXPathContextPtr ctext, request_t *req)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	xmlNodeSetPtr r_nodes = NULL;
	xmlAttrPtr attr = NULL;
	int i, cnt, obj = 0;

	isnslog(LOG_DEBUG, "process_getAssociated_request_from_doc", "entered");
	(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
	    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", ASSOCIATIONTYPE);
	xpath_obj = xmlXPathEvalExpression(expr, ctext);
	if ((xpath_obj) && (xpath_obj->nodesetval) &&
		(xpath_obj->nodesetval->nodeNr > 0) &&
		(xpath_obj->nodesetval->nodeTab)) {
	    for (i = 0; obj_table[i].obj_str != NULL; i++) {
		if (xmlStrncmp(
		    xpath_obj->nodesetval->nodeTab[0]->children->content,
		    (xmlChar *)obj_table[i].obj_str, xmlStrlen(
		    xpath_obj->nodesetval->nodeTab[0]->children->content))
		    == 0) {
		    obj = obj_table[i].obj_id;
		    break;
		}
	    }
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);

	if (obj == 0) {
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	req->op_info.obj = obj;

	if (ISNS_MGMT_OBJECT_TYPE_ENABLED()) {
	    ISNS_MGMT_OBJECT_TYPE(obj);
	}

	switch (obj) {
	    /* using the same algorithm for isns object */
	    case DiscoveryDomainMember:
		(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", NODEOBJECT);
		xpath_obj = xmlXPathEvalExpression(expr, ctext);
		r_nodes = xpath_obj->nodesetval;
		if ((xpath_obj) && (xpath_obj->nodesetval) &&
		    (xpath_obj->nodesetval->nodeNr > 0) &&
		    (xpath_obj->nodesetval->nodeTab)) {
		    req->assoc_req = member_to_container;
		} else {
		    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
		    DDOBJECT);
		    xpath_obj = xmlXPathEvalExpression(expr, ctext);
		    r_nodes = xpath_obj->nodesetval;
		    if ((xpath_obj) && (xpath_obj->nodesetval) &&
			(xpath_obj->nodesetval->nodeNr > 0) &&
			(xpath_obj->nodesetval->nodeTab)) {
			req->assoc_req = container_to_member;
		    } else {
			if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			return (ERR_XML_VALID_OBJECT_NOT_FOUND);
		    }
		}
		break;
	    case DiscoveryDomainSetMember:
		(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", DDSETOBJECT);
		xpath_obj = xmlXPathEvalExpression(expr, ctext);
		r_nodes = xpath_obj->nodesetval;
		if ((xpath_obj) && (xpath_obj->nodesetval) &&
		    (xpath_obj->nodesetval->nodeNr > 0) &&
		    (xpath_obj->nodesetval->nodeTab)) {
		    req->assoc_req = container_to_member;
		} else {
		    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
			DDOBJECT);
		    xpath_obj = xmlXPathEvalExpression(expr, ctext);
		    r_nodes = xpath_obj->nodesetval;
		    if ((xpath_obj) && (xpath_obj->nodesetval) &&
			(xpath_obj->nodesetval->nodeNr > 0) &&
			(xpath_obj->nodesetval->nodeTab)) {
			req->assoc_req = member_to_container;
		    } else {
			if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			return (ERR_XML_VALID_OBJECT_NOT_FOUND);
		    }
		}
		break;
	    default:
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		return (ERR_XML_OP_FAILED);
	}

	/* now process the name attr */
	cnt = r_nodes->nodeNr;
	req->count = 0;
	req->req_data.data = (xmlChar **) malloc(sizeof (xmlChar *));
	/* for (i = cnt - 1; i >= 0; i--) { */
	for (i = 0; i < cnt; i++) {
	    attr = r_nodes->nodeTab[i]->properties;
	    for (; attr != NULL; attr = attr->next) {
		if (xmlStrncmp(attr->name, (xmlChar *)NAMEATTR,
		    xmlStrlen((xmlChar *)NAMEATTR)) == 0) {
			req->req_data.data =
			    NEW_REQARGV(req->req_data.data, req->count);
			if (req->req_data.data == (xmlChar **)NULL) {
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_MALLOC_FAILED);
			}
			req->req_data.data[req->count++] =
			xmlNodeGetContent(attr->children);
			req->req_data.data[req->count] = NULL;
		}
	    }
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	return (0);
}

/*
 * process_delete_request_from_doc --
 *	    first looks for the object through the context ptr and sets the
 *	    request with additional data.
 *	    For DD and DD set, the name is given.
 *	    For DD and DD set membership, container and member pairs are given.
 *
 * ctext: context ptr for the original doc to parse request info.
 * req: request to be filled up.
 *
 * Returns 0 if successful or an error code otherwise.
 */
static int
process_delete_request_from_doc(xmlXPathContextPtr ctext, request_t *req)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	xmlNodeSetPtr r_nodes = NULL;
	xmlAttrPtr attr = NULL;
	xmlChar *container = NULL, *member = NULL;
	int i, cnt;

	int obj = 0;

	isnslog(LOG_DEBUG, "process_delete_request_from_doc", "entered");
	for (i = 0; obj_table[i].obj_str != NULL; i++) {
	    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
		obj_table[i].obj_str);
	    xpath_obj = xmlXPathEvalExpression(expr, ctext);
	    if ((xpath_obj) && (xpath_obj->nodesetval) &&
		(xpath_obj->nodesetval->nodeNr > 0) &&
		(xpath_obj->nodesetval->nodeTab)) {
		obj = obj_table[i].obj_id;
		break;
	    }
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	}

	if (obj == 0) {
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	req->op_info.obj = obj;

	if (ISNS_MGMT_OBJECT_TYPE_ENABLED()) {
	    ISNS_MGMT_OBJECT_TYPE(obj);
	}

	switch (obj) {
	    case DiscoveryDomainMember:
		/* at least one object exists to get here. */
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.pair =
		(assoc_pair_t **)malloc(sizeof (assoc_pair_t *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				container =
				xmlNodeGetContent(attr->children);
			}
			if (xmlStrncmp(attr->name, (xmlChar *)NODENAMEATTR,
			    xmlStrlen((xmlChar *)NODENAMEATTR)) == 0) {
				member =
				xmlNodeGetContent(attr->children);
			}
		    }
		    if (container != NULL && member != NULL) {
			    req->req_data.pair =
			    NEW_REQPAIRARGV(req->req_data.pair, req->count);
			    if (req->req_data.pair == (assoc_pair_t **)NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count] = (assoc_pair_t *)
				malloc(sizeof (assoc_pair_t));
			    if (req->req_data.pair[req->count] == NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count]->container =
				container;
			    req->req_data.pair[req->count]->member =
				member;
			    req->req_data.data[++req->count] = NULL;
		    } else {
			    if (container != NULL) {
				xmlFree(container);
			    }
			    if (member != NULL) {
				xmlFree(member);
			    }
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_XML_OP_FAILED);
		    }
		    container = NULL;
		    member = NULL;
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case DiscoveryDomainSetMember:
		/* at least one object exists to get here. */
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.pair =
		(assoc_pair_t **)malloc(sizeof (assoc_pair_t *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDSETNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				container =
				xmlNodeGetContent(attr->children);
			}
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)NODENAMEATTR)) == 0) {
				member =
				xmlNodeGetContent(attr->children);
			}
		    }
		    if (container != NULL && member != NULL) {
			    req->req_data.pair =
			    NEW_REQPAIRARGV(req->req_data.pair, req->count);
			    if (req->req_data.pair == (assoc_pair_t **)NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count] = (assoc_pair_t *)
				malloc(sizeof (assoc_pair_t));
			    if (req->req_data.pair[req->count] == NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count]->container =
				container;
			    req->req_data.pair[req->count++]->member =
				member;
			    req->req_data.data[req->count] = NULL;
		    } else {
			    if (container != NULL) {
				xmlFree(container);
			    }
			    if (member != NULL) {
				xmlFree(member);
			    }
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_XML_OP_FAILED);
		    }
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case DiscoveryDomain:
	    case DiscoveryDomainSet:
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.data = (xmlChar **) malloc(sizeof (xmlChar *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)NAMEATTR,
			    xmlStrlen((xmlChar *)NAMEATTR)) == 0) {
				req->req_data.data =
				    NEW_REQARGV(req->req_data.data, req->count);
				if (req->req_data.data == (xmlChar **)NULL) {
				    if (xpath_obj)
					xmlXPathFreeObject(xpath_obj);
				    return (ERR_MALLOC_FAILED);
				}
				req->req_data.data[req->count] =
				xmlNodeGetContent(attr->children);
				req->req_data.data[++req->count] = NULL;
			}
		    }
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    default:
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		return (ERR_XML_OP_FAILED);
	}

	return (0);
}

/*
 * process_createModify_request_from_doc --
 *	    first looks for the object through the context ptr and sets the
 *	    request with additional data.
 *	    For DD and DD set, the name is given.
 *	    For DD and DD set membership, container and member pairs are given.
 *
 * ctext: context ptr for the original doc to parse request info.
 * req: request to be filled up.
 *
 * Returns 0 if successful or an error code otherwise.
 */
static int
process_createModify_request_from_doc(xmlXPathContextPtr ctext, request_t *req)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;
	xmlNodeSetPtr r_nodes = NULL;
	xmlAttrPtr attr = NULL;
	xmlChar *container = NULL, *member = NULL, *xml_id;
	int i, cnt;

	int obj = 0;

	isnslog(LOG_DEBUG, "process_createModify_request_from_doc", "entered");
	for (i = 0; obj_table[i].obj_str != NULL; i++) {
	    (void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		XMLSTRING_CAST "%s\"%s\"]", "//*[name()=",
		obj_table[i].obj_str);
	    xpath_obj = xmlXPathEvalExpression(expr, ctext);
	    if ((xpath_obj) && (xpath_obj->nodesetval) &&
		(xpath_obj->nodesetval->nodeNr > 0) &&
		(xpath_obj->nodesetval->nodeTab)) {
		obj = obj_table[i].obj_id;
		break;
	    }
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	}

	if (obj == 0) {
	    return (ERR_XML_VALID_OBJECT_NOT_FOUND);
	}

	req->op_info.obj = obj;

	if (ISNS_MGMT_OBJECT_TYPE_ENABLED()) {
	    ISNS_MGMT_OBJECT_TYPE(obj);
	}

	switch (obj) {
	    case DiscoveryDomainMember:
		/* at least one object exists to get here. */
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.pair =
		(assoc_pair_t **)malloc(sizeof (assoc_pair_t *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				container =
				xmlNodeGetContent(attr->children);
			}
			if (xmlStrncmp(attr->name, (xmlChar *)NODENAMEATTR,
			    xmlStrlen((xmlChar *)NODENAMEATTR)) == 0) {
				member =
				xmlNodeGetContent(attr->children);
			}
		    }
		    if (container != NULL && member != NULL) {
			    req->req_data.pair =
			    NEW_REQPAIRARGV(req->req_data.pair, req->count);
			    if (req->req_data.pair == (assoc_pair_t **)NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count] = (assoc_pair_t *)
				malloc(sizeof (assoc_pair_t));
			    if (req->req_data.pair[req->count] == NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count]->container =
				container;
			    req->req_data.pair[req->count]->member =
				member;
			    req->req_data.data[++req->count] = NULL;
		    } else {
			    if (container != NULL) {
				xmlFree(container);
			    }
			    if (member != NULL) {
				xmlFree(member);
			    }
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_XML_OP_FAILED);
		    }
		    container = member = NULL;
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case DiscoveryDomainSetMember:
		/* at least one object exists to get here. */
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.pair =
		(assoc_pair_t **)malloc(sizeof (assoc_pair_t *));
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDSETNAMEATTR,
			    xmlStrlen((xmlChar *)DDSETNAMEATTR)) == 0) {
				container =
				xmlNodeGetContent(attr->children);
			}
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				member =
				xmlNodeGetContent(attr->children);
			}
		    }
		    if (container != NULL && member != NULL) {
			    req->req_data.pair =
			    NEW_REQPAIRARGV(req->req_data.pair, req->count);
			    if (req->req_data.pair == (assoc_pair_t **)NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count] = (assoc_pair_t *)
				malloc(sizeof (assoc_pair_t));
			    if (req->req_data.pair[req->count] == NULL) {
				if (xpath_obj) xmlXPathFreeObject(xpath_obj);
				return (ERR_MALLOC_FAILED);
			    }
			    req->req_data.pair[req->count]->container =
				container;
			    req->req_data.pair[req->count]->member =
				member;
			    req->req_data.data[++req->count] = NULL;
		    } else {
			    if (container != NULL) {
				xmlFree(container);
			    }
			    if (member != NULL) {
				xmlFree(member);
			    }
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_XML_OP_FAILED);
		    }
		    container = member = NULL;
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case DiscoveryDomain:
	    case DiscoveryDomainSet:
		/* at least one object exists to get here. */
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		req->count = 0;
		req->req_data.attrlist =
		(object_attrlist_t **)malloc(sizeof (object_attrlist_t *));
		for (i = 0; i < cnt; i++) {
		    req->req_data.attrlist =
			NEW_REQATTRLISTARGV(req->req_data.attrlist, req->count);
		    if (req->req_data.attrlist ==
			(object_attrlist_t **)NULL) {
			if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			return (ERR_MALLOC_FAILED);
		    }
		    req->req_data.attrlist[req->count] = (object_attrlist_t *)
			malloc(sizeof (object_attrlist_t));
		    if (req->req_data.attrlist[req->count] == NULL) {
			if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			return (ERR_MALLOC_FAILED);
		    }
		    req->req_data.attrlist[req->count]->name = NULL;
		    req->req_data.attrlist[req->count]->id = NULL;
		    req->req_data.attrlist[req->count]->enabled = NULL;
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if ((xmlStrncmp(attr->name, (xmlChar *)NAMEATTR,
			    xmlStrlen((xmlChar *)NAMEATTR))) == 0) {
				req->req_data.attrlist[req->count]->name =
				xmlNodeGetContent(attr->children);
			}
			if ((xmlStrncmp(attr->name, (xmlChar *)IDATTR,
			    xmlStrlen((xmlChar *)IDATTR))) == 0) {
				req->req_data.attrlist[req->count]->id =
				    (uint32_t *)calloc(1, sizeof (uint32_t));
				if (req->req_data.attrlist[req->count]->id ==
				    NULL) {
				    if (xpath_obj)
					xmlXPathFreeObject(xpath_obj);
				    return (ERR_MALLOC_FAILED);
				}
				xml_id = xmlNodeGetContent(attr->children);
				if (xml_id != NULL) {
				    *(req->req_data.attrlist[req->count]->id) =
					atoi((const char *)xml_id);
				    xmlFree(xml_id);
				}
			}
		    }
			/*
			 * check the enabled element.
			 * Only one child element so check the children ptr.
			 */
		    if (r_nodes->nodeTab[i]->children) {
			req->req_data.attrlist[req->count]->enabled =
			    (boolean_t *)malloc(sizeof (boolean_t));
			if (req->req_data.attrlist[req->count]->enabled
			    == NULL) {
			    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
			    return (ERR_MALLOC_FAILED);
			}
			/* value is children of enabled. */
			if (xmlStrncmp(
			    r_nodes->nodeTab[i]->children->children->content,
			    (xmlChar *)XMLTRUE, xmlStrlen((xmlChar *)XMLTRUE))
			    == 0) {
			    *(req->req_data.attrlist[req->count]->enabled)
				= B_TRUE;
			} else {
			    *(req->req_data.attrlist[req->count]->enabled)
				= B_FALSE;
			}
		    }
		    req->req_data.attrlist[++req->count] = NULL;
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    default:
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		return (ERR_XML_OP_FAILED);
	}

	return (0);
}

/*
 * build_mgmt_request -- extracts the request info from the given XML doc.
 *
 * x_doc: ptr to the request XML doc
 * req: ptr to the request struct to be filled up.
 *
 * Return value: ISNS_RSP_SUCCESSFUL if successful or an error code.
 */
static int
process_mgmt_request(xmlDocPtr x_doc, request_t *req, ucred_t *uc)
{
	result_code_t   ret;
	int		op;
	xmlXPathContextPtr ctext = NULL;
	uid_t			user;
	struct passwd		pwds, *pwd;
	char			buf_pwd[1024];


	isnslog(LOG_DEBUG, "process_mgmt_request", "entered");
	(void) memset(req, 0, sizeof (request_t));
	/* get the operation first. */
	ctext = xmlXPathNewContext(x_doc);
	if (ctext == NULL) {
	    return (ERR_XML_FAILED_TO_SET_XPATH_CONTEXT);
	}

	isnslog(LOG_DEBUG, "process_mgmt_request", "xpath context succeeded");
	op = get_op_id_from_doc(ctext);
	if (op == -1) {
	    if (ctext) xmlXPathFreeContext(ctext);
	    return (ERR_XML_VALID_OPERATION_NOT_FOUND);
	}

	user = ucred_getruid(uc);
	ret = getpwuid_r(user, &pwds, buf_pwd, sizeof (buf_pwd), &pwd);
	if (ret != 0) {
	    if (ctext) xmlXPathFreeContext(ctext);
	    return (ERR_DOOR_SERVER_DETECTED_INVALID_USER);
	}

	/* write operations are restricted. */
	if ((op == delete_op) || (op == createModify_op)) {
	    if (!chkauthattr(ISNS_ADMIN_WRITE_AUTH, pwd->pw_name)) {
		if (ctext) xmlXPathFreeContext(ctext);
		return (ERR_DOOR_SERVER_DETECTED_NOT_AUTHORIZED_USER);
	    }
	}

	req->op_info.op = op;

	if (ISNS_MGMT_OPERATION_TYPE_ENABLED()) {
	    ISNS_MGMT_OPERATION_TYPE(op);
	}

	switch (op) {
	    case (get_op):
		ret = process_get_request_from_doc(ctext, req);
		break;
	    case (getAssociated_op):
		ret = process_getAssociated_request_from_doc(ctext, req);
		break;
	    case (enumerate_op):
		ret = process_enumerate_request_from_doc(ctext, req);
		break;
	    case (delete_op):
		ret = process_delete_request_from_doc(ctext, req);
		break;
	    case (createModify_op):
		ret = process_createModify_request_from_doc(ctext, req);
		break;
	    default:
		ret = ERR_XML_VALID_OPERATION_NOT_FOUND;
	}

	if (ctext) xmlXPathFreeContext(ctext);
	return (ret);
}

/*
 * build_mgmt_response -- sets an XML doc with a root and calls a porper
 *	    routine based on the request.  If the called routine constructed
 *	    the response doc with the result element, this routine fills up
 *	    response buffer with raw XML doc.
 *
 * reponse: ptr to response buffer
 * req: request to be processed.
 * size: ptr to the response doc buffer
 */
static int
build_mgmt_response(xmlChar **response, request_t req, int *size)
{

	int ret;
	xmlDocPtr	doc;
	xmlNodePtr	root;
	xmlXPathContextPtr ctext = NULL;
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlXPathObjectPtr xpath_obj = NULL;

	isnslog(LOG_DEBUG, "build_mgmt_response", "entered");

	doc = xmlNewDoc((uchar_t *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)ISNSRESPONSE);
	(void) xmlDocSetRootElement(doc, root);
	if (xmlSetProp(root, (xmlChar *)XMLNSATTR, (xmlChar *)XMLNSATTRVAL) ==
	    NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	switch (req.op_info.op) {
	    case get_op:
		switch (req.op_info.obj) {
		    case Node:
			ret = get_node_op(&req, doc);
			break;
		    case DiscoveryDomain:
			ret = get_dd_op(&req, doc);
			break;
		    case DiscoveryDomainSet:
			ret = get_ddset_op(&req, doc);
			break;
		    case ServerConfig:
			ret = get_serverconfig_op(doc);
			break;
		    default:
			ret = ERR_INVALID_MGMT_REQUEST;
		}
		break;
	    case enumerate_op:
		isnslog(LOG_DEBUG, "build_mgmt_response", "enumerate_op");
		switch (req.op_info.obj) {
		    case Node:
			ret = enumerate_node_op(doc);
			break;
		    case DiscoveryDomain:
			ret = enumerate_dd_op(doc);
			break;
		    case DiscoveryDomainSet:
			ret = enumerate_ddset_op(doc);
			break;
		    default:
			ret = ERR_INVALID_MGMT_REQUEST;
		}
		break;
	    case getAssociated_op:
		switch (req.op_info.obj) {
		    case DiscoveryDomainMember:
			if (req.assoc_req == container_to_member) {
			    ret = getAssociated_dd_to_node_op(&req, doc);
			} else {
			    ret = getAssociated_node_to_dd_op(&req, doc);
			}
			break;
		    case DiscoveryDomainSetMember:
			if (req.assoc_req == container_to_member) {
			    ret = getAssociated_ddset_to_dd_op(&req, doc);
			} else {
			    ret = getAssociated_dd_to_ddset_op(&req, doc);
			}
			break;
		    default:
			ret = ERR_INVALID_MGMT_REQUEST;
		}
		break;
	    case createModify_op:
		switch (req.op_info.obj) {
		    case DiscoveryDomain:
		    case DiscoveryDomainSet:
			ret = createModify_dd_ddset_op(&req, doc);
			break;
		    case DiscoveryDomainMember:
		    case DiscoveryDomainSetMember:
			ret = create_ddmember_ddsetmember_op(&req, doc,
			    req.op_info.obj);
			break;
		    default:
			ret = ERR_INVALID_MGMT_REQUEST;
		}
		break;
	    case delete_op:
		switch (req.op_info.obj) {
		    case DiscoveryDomainMember:
		    case DiscoveryDomainSetMember:
			ret = delete_ddmember_ddsetmember_op(&req, doc,
			    req.op_info.obj);
			break;
		    case DiscoveryDomain:
		    case DiscoveryDomainSet:
			ret = delete_dd_ddset_op(&req, doc, req.op_info.obj);
			break;
		    default:
			ret = ERR_INVALID_MGMT_REQUEST;
		}
		break;
	    default:
		ret = ERR_INVALID_MGMT_REQUEST;
	}

	/*
	 * if failed check to see the doc contains the result element.
	 * if not, the response is set with only an error code.
	 */
	if (ret != ISNS_RSP_SUCCESSFUL) {
	    ctext = xmlXPathNewContext(doc);
	    if (ctext != NULL) {
		(void) xmlStrPrintf(expr, ISNS_MAX_LABEL_LEN + 13,
		    XMLSTRING_CAST "%s\"%s\"]", "//*[name()=", RESULT);
		xpath_obj = xmlXPathEvalExpression(expr, ctext);
		if ((xpath_obj == NULL) || (xpath_obj->nodesetval == NULL) ||
		    (xpath_obj->nodesetval->nodeNr <= 0) ||
		    (xpath_obj->nodesetval->nodeTab == NULL)) {
		    isnslog(LOG_DEBUG,
			"build_mgmt_response",
			"returning repsonse only with error code %d\n", ret);
			*response = malloc(sizeof (ret));
			if (*response) **response = ret;
			*size = sizeof (ret);
		} else {
		    xmlDocDumpMemory(doc, response, size);
		}
	    } else {
		/* can't verify the xml doc. dump return the doc anyway. */
		xmlDocDumpMemory(doc, response, size);
	    }
	} else {
	    xmlDocDumpMemory(doc, response, size);
	}

	if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	if (ctext) xmlXPathFreeContext(ctext);
	if (doc) xmlFreeDoc(doc);
	return (ret);
}

/*
 * build_result_message -- construct a response doc with the given result.
 *	    Result contains status code and message.
 *
 * reponse: ptr to response doc
 * code: result code
 * size: ptr to the response doc size
 */
static int
build_result_message(xmlChar **response, result_code_t code, int *size)
{
	int ret = ISNS_RSP_SUCCESSFUL;
	xmlDocPtr	doc;
	xmlNodePtr	root, n_obj;
	char		numbuf[32];

	isnslog(LOG_DEBUG, "build_result_response", "entered");

	doc = xmlNewDoc((uchar_t *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)ISNSRESPONSE);
	(void) xmlDocSetRootElement(doc, root);

	n_obj = xmlNewChild(root, NULL, (xmlChar *)RESULT, NULL);

	if (code == ISNS_RSP_SUCCESSFUL) {
	    (void) sprintf(numbuf, "%d", ISNS_RSP_SUCCESSFUL);
	    if (xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		(xmlChar *)numbuf) == NULL) {
		ret = ERR_XML_NEWCHILD_FAILED;
	    }
	} else {
	    (void) sprintf(numbuf, "%d", code);
	    if (xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		(xmlChar *)numbuf) == NULL) {
		ret = ERR_XML_NEWCHILD_FAILED;
	    }
	    if (xmlNewChild(n_obj, NULL, (xmlChar *)MESSAGEELEMENT,
		(xmlChar *)result_code_to_str(code)) == NULL) {
		ret = ERR_XML_NEWCHILD_FAILED;
	    }
	}

	xmlDocDumpMemory(doc, response, size);

	if (doc) xmlFreeDoc(doc);
	return (ret);
}

/*
 * cleanup_request -- deallocatate memory associated with the given request
 *	    structure.
 */
static void
cleanup_request(request_t req)
{
	int i;

	isnslog(LOG_DEBUG, "cleanup_request", "entered");
	switch (req.op_info.op) {
	    case (get_op):
		for (i = 0; i < req.count; i++) {
		    if (req.req_data.data[i])
			xmlFree(req.req_data.data[i]);
		}
		if (req.req_data.data) free(req.req_data.data);
		break;
	    case (getAssociated_op):
		for (i = 0; i < req.count; i++) {
		    if (req.req_data.data[i])
			xmlFree(req.req_data.data[i]);
		}
		if (req.req_data.data) free(req.req_data.data);
		break;
	    case (enumerate_op):
		break;
	    case (delete_op):
		if ((req.op_info.obj == DiscoveryDomainMember) ||
		    (req.op_info.obj == DiscoveryDomainSetMember)) {
		    for (i = 0; i < req.count; i++) {
			if (req.req_data.pair[i]->container)
			    xmlFree(req.req_data.pair[i]->container);
			if (req.req_data.pair[i]->member)
			    xmlFree(req.req_data.pair[i]->member);
			if (req.req_data.pair[i])
			    free(req.req_data.pair[i]);
		    }
		    if (req.req_data.pair) free(req.req_data.pair);
		} else {
		    for (i = 0; i < req.count; i++) {
			if (req.req_data.data[i])
			    xmlFree(req.req_data.data[i]);
		    }
		    if (req.req_data.data) free(req.req_data.data);
		}
		break;
	    case (createModify_op):
		if ((req.op_info.obj == DiscoveryDomainMember) ||
		    (req.op_info.obj == DiscoveryDomainSetMember)) {
		    for (i = 0; i < req.count; i++) {
			if (req.req_data.pair[i]->container)
			    xmlFree(req.req_data.pair[i]->container);
			if (req.req_data.pair[i]->member)
			    xmlFree(req.req_data.pair[i]->member);
			if (req.req_data.pair[i])
			    free(req.req_data.pair[i]);
		    }
		    if (req.req_data.pair) free(req.req_data.pair);
		} else if ((req.op_info.obj == DiscoveryDomain) ||
		    (req.op_info.obj == DiscoveryDomainSet)) {
		    for (i = 0; i < req.count; i++) {
			if (req.req_data.attrlist[i]->name)
			    xmlFree(req.req_data.attrlist[i]->name);
			if (req.req_data.attrlist[i]->id)
			    free(req.req_data.attrlist[i]->id);
			if (req.req_data.attrlist[i]->enabled)
			    free(req.req_data.attrlist[i]->enabled);
			if (req.req_data.pair[i])
			    free(req.req_data.pair[i]);
		    }
		    if (req.req_data.attrlist) free(req.req_data.attrlist);
		}
		break;
	}
}

/*
 * Find a matching entry for the given thread id.
 */
static thr_elem_t *match_entry(pthread_t tid)
{

	thr_elem_t *thr = thr_list;

	while (thr) {
	    if (pthread_equal(thr->thr_id, tid)) {
		return (thr);
	    }
	    thr = thr->next;
	}

	return (NULL);
}

/*
 * Add an entry to the thr_list for the given thread id.
 */
static int
add_entry(pthread_t tid, xmlChar *doc)
{

	thr_elem_t *new_e;
	thr_elem_t *thr = thr_list;

	if ((new_e = malloc(sizeof (thr_elem_t))) == NULL) {
	    return (ERR_MALLOC_FAILED);
	}
	new_e->thr_id = tid;
	new_e->doc = doc;
	new_e->next = NULL;

	if (thr_list == NULL) {
	    thr_list = new_e;
	} else {
	    while (thr->next) {
		thr = thr->next;
	    }
	    thr->next = new_e;
	}

	return (ISNS_RSP_SUCCESSFUL);
}

/*
 * door_server -- proecess the management request and send response back
 *		the client.
 *
 * In order to handle allocation after door_return,
 * a global list, thr_list, is maintained to free the response buffer
 * from the previous invocation of the server function on the same thread.
 * Note:  the door framework creates a thread and the same thread is used
 * while a new thread is created for concurrent door_calls.
 *
 * If a thread is used once the buffer will be left allocated.
 */
/*ARGSUSED*/
static void
door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	request_t		req;
	xmlDocPtr		x_doc;
	xmlChar			*resp_buf = NULL;
	int			ret, size = 0;
	pthread_t		tid;
	thr_elem_t		*thr;
	ucred_t			*uc = NULL;

	if (ISNS_MGMT_REQUEST_RECEIVED_ENABLED()) {
	    ISNS_MGMT_REQUEST_RECEIVED();
	}

	if (door_ucred(&uc) != 0) {
	    isnslog(LOG_DEBUG, "door_server",
		"door_ucred failed. errno: %d\n", errno);
	    ret = build_result_message(&resp_buf,
		ERR_DOOR_UCRED_FAILED, &size);
	    if (ret == ISNS_RSP_SUCCESSFUL) {
		(void) door_return((char *)resp_buf, size + 1,  NULL, 0);
		/* Not reached */
	    } else {
		ret = ERR_DOOR_UCRED_FAILED;
		(void) door_return((void *)&ret, sizeof (ret),  NULL, 0);
		/* Not reached */
	    }
	}

	isnslog(LOG_DEBUG, "door_server", "entered with request:\n %s\n", argp);
	if ((x_doc = xmlParseMemory(argp, arg_size)) != NULL) {
		isnslog(LOG_DEBUG, "door_server", "ParseMemory succeeded");
		if ((ret = process_mgmt_request(x_doc, &req, uc)) == 0) {
		    ret = build_mgmt_response(&resp_buf, req, &size);
		} else {
		    ret = build_result_message(&resp_buf, ret, &size);
		}
		xmlFreeDoc(x_doc);
		cleanup_request(req);
	} else {
		ret = build_result_message(&resp_buf,
		    ERR_XML_PARSE_MEMORY_FAILED, &size);
	}

	/* free the ucred */
	ucred_free(uc);

	if (resp_buf) {
	    tid = pthread_self();
	    if ((thr = match_entry(tid)) == NULL) {
		(void) add_entry(tid, resp_buf);
	    } else {
		isnslog(LOG_DEBUG, "door_server",
		    "free the previouly returned buffer %x on this thread\n",
		    thr->doc);
		xmlFree(thr->doc);
		isnslog(LOG_DEBUG, "door_server",
		    "store the currently allocated buffer %x on this thread\n",
		    resp_buf);
		thr->doc = resp_buf;
	    }
	    isnslog(LOG_DEBUG,
		"door_server", "exiting with response:\n %s\n",
		    (const char *)resp_buf);

	    if (ISNS_MGMT_REQUEST_RESPONDED_ENABLED()) {
		ISNS_MGMT_REQUEST_RESPONDED();
	    }

	    (void) door_return((char *)resp_buf, size + 1,  NULL, 0);
		/* Not reached */
	}

	isnslog(LOG_DEBUG,
	    "door_server", "exiting only with error code %d\n", ret);

	if (ISNS_MGMT_REQUEST_RESPONDED_ENABLED()) {
	    ISNS_MGMT_REQUEST_RESPONDED();
	}

	(void) door_return((void *)&ret, sizeof (ret),  NULL, 0);

}

/*
 * setup_mgmt_door -- Create a door portal for management application requests
 *
 * First check to see if another daemon is already running by attempting
 * to send an empty request to the door. If successful it means this
 * daemon should exit.
 */
int
setup_mgmt_door(msg_queue_t *sys_q)
{
	int fd, door_id;
	struct stat buf;
	door_arg_t darg;

	isnslog(LOG_DEBUG, "setup_mgmt_door", "entered");
	/* check if a door is already running. */
	if ((fd = open(ISNS_DOOR_NAME, 0)) >= 0) {
		darg.data_ptr = "<?xml version='1.0' encoding='UTF-8'?>"
				"<isnsRequest><get><isnsObject>"
				"<DiscoveryDomain name=\"default\">"
				"</DiscoveryDomain></isnsObject></get>"
				"</isnsRequest>";
		darg.data_size = xmlStrlen((xmlChar *)darg.data_ptr) + 1;
		darg.desc_ptr = NULL;
		darg.desc_num = 0;
		darg.rbuf = NULL;
		darg.rsize = 0;

		if (door_call(fd, &darg) == 0) {
			/* door already running. */
			(void) close(fd);
			isnslog(LOG_DEBUG, "setup_mgmt_door",
			    "management door is already runninng.");
			if (darg.rsize > darg.data_size) {
			    (void) munmap(darg.rbuf, darg.rsize);
			}
			door_created = B_FALSE;
			return (0);
		}
		(void) close(fd);
	}

	if ((door_id = door_create(door_server, (void *)sys_q, 0)) < 0) {
		isnslog(LOG_DEBUG, "setup_mgmt_door",
			"Failed to create managment door");
		exit(1);
	}

	if (stat(ISNS_DOOR_NAME, &buf) < 0) {
	    if ((fd = creat(ISNS_DOOR_NAME, 0666)) < 0) {
		isnslog(LOG_DEBUG, "setup_mgmt_door",
		    "open failed on %s errno = %d", ISNS_DOOR_NAME, errno);
		exit(1);
	    }
	    (void) close(fd);
	}

	/* make sure the file permission set to general access. */
	(void) chmod(ISNS_DOOR_NAME, 0666);
	(void) fdetach(ISNS_DOOR_NAME);

	if (fattach(door_id, ISNS_DOOR_NAME) < 0) {
		syslog(LOG_DEBUG, "setup_mgmt_door",
		    "fattach failed on %s errno=%d",
		    ISNS_DOOR_NAME, errno);
		return (-1);
	}

	door_created = B_TRUE;

	return (0);
}
