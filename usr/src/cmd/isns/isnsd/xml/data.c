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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "isns_server.h"
#include "isns_obj.h"
#include "isns_log.h"

#if LIBXML_VERSION >= 20904
#define	XMLSTRING_CAST (const char *)
#else
#define	XMLSTRING_CAST (const xmlChar *)
#endif

/*
 * external variables
 */
extern const int NUM_OF_ATTRS[MAX_OBJ_TYPE_FOR_SIZE];
extern const int TYPE_OF_PARENT[MAX_OBJ_TYPE_FOR_SIZE];
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];

extern char data_store[MAXPATHLEN];

/*
 * local variables
 */
static xmlDocPtr xml_doc = NULL;
static char *xml_file = NULL;
static char *xml_tmp_file = NULL;
static char *xml_bak_file = NULL;

static const int OBJ_DTD_ORDER[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	1,	/* OBJ_ENTITY */
	2,	/* OBJ_ISCSI */
	3,	/* OBJ_PORTAL */
	4,	/* OBJ_PG */
	5,	/* OBJ_DD */
	6,	/* OBJ_DDS */
	0,	/* MAX_OBJ_TYPE */
	0,	/* OBJ_DUMMY1 */
	0,	/* OBJ_DUMMY2 */
	0,	/* OBJ_DUMMY3 */
	0,	/* OBJ_DUMMY4 */
	12,	/* OBJ_ASSOC_ISCSI */
	14,	/* OBJ_ASSOC_DD */
};

#define	DEF_XML_ROOT(ISNS_DATA, VENDOR, SMI, VERSION, ONE_DOT_O) \
	(xmlChar *)ISNS_DATA, \
	(xmlChar *)VENDOR, \
	(xmlChar *)SMI, \
	(xmlChar *)VERSION, \
	(xmlChar *)ONE_DOT_O
static const xmlChar *xml_root[] = {
#include "data.def"
};

#define	DEF_XML_DATA(TAG, TYPE, ARG1, ARG2) (xmlChar *)TAG,
static const xmlChar* xmlTag[] = {
#include "data.def"
};

#define	DEF_XML_DATA(TAG, TYPE, ARG1, ARG2) TYPE,
static const char *xmlType[] = {
#include "data.def"
};

#define	DEF_XML_DATA(TAG, TYPE, ARG1, ARG2) ARG1,
static const int xmlArg1[] = {
#include "data.def"
};

#define	DEF_XML_DATA(TAG, TYPE, ARG1, ARG2) ARG2,
static const int xmlArg2[] = {
#include "data.def"
};

#define	DEF_XML_PROP(INDEX, TYPE, NAME, TAG, ID) TYPE,
static const unsigned char xmlPropType[] = {
#include "data.def"
};

#define	DEF_XML_PROP(INDEX, TYPE, NAME, TAG, ID) (xmlChar *)NAME,
static const xmlChar *xmlPropName[] = {
#include "data.def"
};

#define	DEF_XML_PROP(INDEX, TYPE, NAME, TAG, ID) TAG,
static const int xmlPropTag[] = {
#include "data.def"
};

#define	DEF_XML_PROP(INDEX, TYPE, NAME, TAG, ID) ID,
static const int xmlPropID[] = {
#include "data.def"
};

#define	ARRAY_LENGTH(ARRAY) (sizeof (ARRAY) / sizeof (ARRAY[0]))

/*
 * ****************************************************************************
 *
 * get_index_by_name:
 *	find the index in the global tables for the name of an attribute.
 *
 * name - the name of an attribute.
 * return - index or -1 for error.
 *
 * ****************************************************************************
 */
static int
get_index_by_name(
	const xmlChar *name
)
{
	int i;
	for (i = 0; i < ARRAY_LENGTH(xmlTag); i++) {
		if (xmlStrEqual(xmlTag[i], name)) {
			return (i);
		}
	}
	return (-1);
}

/*
 * ****************************************************************************
 *
 * get_index_by_otype:
 *	find the index in the global tables for the type of an object.
 *
 * name - the type of an object.
 * return - index or -1 for error.
 *
 * ****************************************************************************
 */
static int
get_index_by_otype(
	int otype
)
{
	int i;
	for (i = 0; i < ARRAY_LENGTH(xmlTag); i++) {
		if (xmlArg1[i] == otype && xmlType[i][0] == 'o') {
			return (i);
		}
	}
	return (-1);
}

/*
 * ****************************************************************************
 *
 * get_index_by_tag:
 *	find the index in the global tables for the tag of an attribute.
 *
 * name - the tag of an attribute.
 * return - index or -1 for error.
 *
 * ****************************************************************************
 */
static int
get_index_by_tag(
	int tag
)
{
	int i;
	for (i = 0; i < ARRAY_LENGTH(xmlTag); i++) {
		if (xmlArg1[i] == tag &&
		    xmlType[i][0] != 'o' &&
		    xmlType[i][0] != 'a') {
			return (i);
		}
	}
	return (-1);
}

/*
 * ****************************************************************************
 *
 * get_xml_doc:
 *	open the xml file and assign the global xml doc if the xml file
 *	is not opened, set the doc pointer with the opened xml file for
 *	returnning.
 *
 * docp - the doc pointer for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
get_xml_doc(
	xmlDocPtr *docp
)
{
	int ec = 0;

	if (xml_doc == NULL) {
		/* validate the xml file */

		/* open the xml file */
		xml_doc = xmlParseFile(xml_file);
	}

	*docp = xml_doc;

	if (xml_doc == NULL) {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * close_xml_doc:
 *	close the global xml doc and ignore any changes that has been
 *	made in it.
 *
 * ****************************************************************************
 */
static void
close_xml_doc(
)
{
	if (xml_doc) {
		/* just close it */
		xmlFreeDoc(xml_doc);
		xml_doc = NULL;
	}
}

/*
 * ****************************************************************************
 *
 * convert_xml2attr:
 *	convert a xml data to a TLV format isns attribute.
 *
 * tag - the tag of attribute.
 * type - the data type of the xml data.
 * value - the xml data.
 * attr - TLV format attribute for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
convert_xml2attr(
	const int tag,
	const unsigned char type,
	xmlChar *value,
	isns_attr_t *attr
)
{
	uint32_t len;
	int ec = 0;

	attr->tag = tag;
	switch (type) {
		case 'u':
			/* 4-bytes non-negative integer */
			attr->len = 4;
			attr->value.ui = atoi((const char *)value);
			break;
		case 's':
			/* literal string */
			len = strlen((char *)value);
			len += 4 - (len % 4);
			attr->len = len;
			attr->value.ptr = (uchar_t *)malloc(attr->len);
			if (attr->value.ptr != NULL) {
				(void) strcpy((char *)attr->value.ptr,
				    (char *)value);
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case 'p':
			/* IPv6 block data */
			attr->len = sizeof (in6_addr_t);
			attr->value.ip = (in6_addr_t *)malloc(attr->len);
			if (attr->value.ip != NULL) {
				(void) inet_pton(AF_INET6,
				    (char *)value,
				    attr->value.ip);
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		default:
			break;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * convert_attr2xml:
 *	convert a TLV format isns attribute to xml node format.
 *
 * node - the xml node where the new node is being added to.
 * attr - the TLV format attribute.
 * name - the name of the attribute in xml node.
 * type - the data type of the attribute.
 * elm_flag - 0: adding a xml attlist.
 *	      1: adding a xml child node.
 *	      2: adding a previous sibling node.
 *	      3: adding a xml content node.
 *	      4: adding a xml attribute.
 * return - xml node.
 *
 * ****************************************************************************
 */
static xmlNodePtr
convert_attr2xml(
	xmlNodePtr node,
	const isns_attr_t *attr,
	const xmlChar *name,
	const char type,
	const int elm_flag
)
{
	xmlChar buff[INET6_ADDRSTRLEN + 1] = { 0 };
	xmlChar *value = NULL;
	xmlNodePtr child = NULL;

	switch (type) {
		case 'u':
			/* 4-bytes non-negative integer */
			if (xmlStrPrintf(buff, sizeof (buff),
			    XMLSTRING_CAST "%u",
			    attr->value.ui) > 0) {
				value = (xmlChar *)&buff;
			}
			break;
		case 's':
			/* literal string */
			value = (xmlChar *)attr->value.ptr;
			break;
		case 'p':
			/* IPv6 block data */
			value = (xmlChar *)inet_ntop(AF_INET6,
			    (char *)attr->value.ip,
			    (char *)buff,
			    sizeof (buff));
			break;
		default:
			break;
	}

	if (!value) {
		return (NULL);
	}

	switch (elm_flag) {
		case 0: /* attlist */
			if (xmlSetProp(node, name, value)) {
				child = node;
			}
			break;
		case 1: /* child element */
			child = xmlNewChild(node, NULL, name, value);
			break;
		case 2: /* prev sibling element */
			child = xmlNewNode(NULL, name);
			if (child != NULL &&
			    xmlAddPrevSibling(node, child) == NULL) {
				xmlFreeNode(child);
				node = NULL;
			} else {
				node = child;
			}
			/* LINTED E_CASE_FALLTHRU */
		case 3: /* set content */
			if (node) {
				xmlNodeSetContent(node, value);
			}
			child = node;
			break;
		case 4: /* new attr value */
			if (xmlSetProp(node, name, value)) {
				child = node;
			}
			break;
		default:
			ASSERT(0);
			break;
	}

	return (child);
}

/*
 * ****************************************************************************
 *
 * parse_xml_prop:
 *	parse the properties of a xml node and convert them to the attributes
 *	of an isns object, these xml properties are the UID attribute and
 *	key attributes of the isns object.
 *
 * node - the xml node that contains the properties.
 * obj - the isns object.
 * i  - the index of the attribute in the global tables.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
parse_xml_prop(
	xmlNodePtr node,
	isns_obj_t *obj,
	int i
)
{
	int ec = 0;
	const char *props = &xmlType[i][1];
	const xmlChar *prop_name;
	xmlChar *prop_value;
	unsigned char prop_type;
	int prop_tag;
	int prop_id;
	char prop;
	int j;

	j = 0;
	prop = props[j ++];
	while (ec == 0 &&
	    prop >= 'a' && prop <= 'z') {
		prop -= 'a';
		prop_id = xmlPropID[prop];
		prop_tag = xmlPropTag[prop];
		prop_name = xmlPropName[prop];
		prop_type = xmlPropType[prop];
		prop_value = xmlGetProp(node, prop_name);

		if (prop_value) {
			ec = convert_xml2attr(
			    prop_tag,
			    prop_type,
			    prop_value,
			    &(obj->attrs[prop_id]));
			xmlFree(prop_value);
		}
		prop = props[j ++];
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * parse_xml_attr:
 *	parse a xml node and convert it to one isns object attribute.
 *	this attribute is the non-key attribute of the isns object.
 *
 * node - the xml node.
 * obj - the isns object.
 * i  - the index of the attribute in the global tables.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
parse_xml_attr(
	xmlNodePtr node,
	isns_obj_t *obj,
	int i
)
{
	int ec = 0;
	const unsigned char attr_type = xmlType[i][0];
	const int attr_tag = xmlArg1[i];
	const int attr_id = xmlArg2[i];
	xmlChar *attr_value;

	attr_value = xmlNodeGetContent(node);

	if (attr_value) {
		ec = convert_xml2attr(
		    attr_tag,
		    attr_type,
		    attr_value,
		    &(obj->attrs[attr_id]));
		xmlFree(attr_value);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * parse_xml_obj:
 *	parse one isns object from the xml doc.
 *
 * nodep - the pointer of the xml node for parsing.
 * objp - the pointer of isns object for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
parse_xml_obj(
	xmlNodePtr *nodep,
	isns_obj_t **objp
)
{
	int ec = 0;
	int i, j;

	xmlNodePtr node = *nodep;
	xmlNodePtr children;

	isns_obj_t *obj = *objp;

	while (node && ec == 0) {
		if (node->type == XML_ELEMENT_NODE) {
			children = node->children;
			i = get_index_by_name(node->name);
			ASSERT(i >= 0);
			j = xmlType[i][0];
			if (j == 'o' && obj == NULL) {
				obj = obj_calloc(xmlArg1[i]);
				if (obj == NULL) {
					ec = ISNS_RSP_INTERNAL_ERROR;
					break;
				}
				if ((ec = parse_xml_prop(node, obj, i)) == 0 &&
				    (children == NULL ||
				    (ec = parse_xml_obj(&children, &obj)) ==
				    0)) {
					if (children != NULL &&
					    children != node->children) {
						*nodep = children;
					}
					*objp = obj;
				} else {
					free_object(obj);
				}
				break;
				/* LINTED E_NOP_IF_STMT */
			} else if (j == 'o') {
			} else if (j != 0) {
				ASSERT(obj);
				if (children != NULL) {
					ec = parse_xml_attr(children, obj, i);
					*nodep = children;
				} else {
					/* assign a default value */
					*nodep = node;
				}
			} else {
				/* unknown xml node */
				break;
			}
			/* LINTED E_NOP_ELSE_STMT */
		} else {
			/* carry return or blank spaces, skip it */
		}
		node = node->next;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * locate_xml_node:
 *	locate the xml node from xml doc by matching the object UID.
 *
 * doc - the xml doc.
 * otype - the matching object type.
 * match_uid - the matching object UID.
 * node - the pointer of matched xml node for returning.
 * context - the xml context for matching process.
 * result - the xml result for matching process.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
locate_xml_node(
	xmlDocPtr doc,
	int otype,
	int match_uid,
	xmlNodePtr *node,
	xmlXPathContextPtr *context,
	xmlXPathObjectPtr *result
)
{
	int ec = 0;

	xmlNodeSetPtr nodeset;
	xmlNodePtr curr;
	xmlChar expr[32] = { (xmlChar)'/', (xmlChar)'/', 0 };

	char prop;
	const xmlChar *prop_name;
	xmlChar *prop_value;
	int uid;

	int i, j;

	*node = NULL;

	i = get_index_by_otype(otype);
	ASSERT(i >= 0);

	*context = xmlXPathNewContext(doc);

	if (*context &&
	    xmlStrPrintf(&expr[2], 30, XMLSTRING_CAST "%s",
	    xmlTag[i]) != -1) {
		*result = xmlXPathEvalExpression(expr, *context);
		if (*result) {
			prop = xmlArg2[i] - 'a';
			prop_name = xmlPropName[prop];
			ASSERT(xmlPropType[prop] == 'u');
			nodeset = (*result)->nodesetval;
			for (j = 0;
			    nodeset && (j < nodeset->nodeNr);
			    j++) {
				curr = nodeset->nodeTab[j];
				prop_value = xmlGetProp(curr, prop_name);
				if (prop_value) {
					uid = atoi((const char *)prop_value);
					xmlFree(prop_value);
					if (uid == match_uid) {
						/* found it */
						*node = curr;
						return (ec);
					}
				}
			}
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	if (*result) {
		xmlXPathFreeObject(*result);
		*result = NULL;
	}
	if (*context) {
		xmlXPathFreeContext(*context);
		*context = NULL;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * make_xml_node:
 *	generate a xml node for presenting an isns object.
 *
 * obj - an isns object.
 * return - the xml node.
 *
 * ****************************************************************************
 */
static xmlNodePtr
make_xml_node(
	const isns_obj_t *obj
)
{
	const isns_attr_t *attr;

	xmlNodePtr node;
	const char *props;
	char prop;
	const xmlChar *name;
	unsigned char type;
	int prop_id;
	int i, j;

	i = get_index_by_otype(obj->type);
	ASSERT(i >= 0);
	node = xmlNewNode(NULL, xmlTag[i]);
	if (!node) {
		return (NULL);
	}

	/* generate xml attributes of the node */
	props = &xmlType[i][1];
	prop = *(props ++);
	while (prop >= 'a' && prop <= 'z') {
		prop -= 'a';
		prop_id = xmlPropID[prop];
		name = xmlPropName[prop];
		type = xmlPropType[prop];
		attr = &obj->attrs[prop_id];
		if (!convert_attr2xml(node, attr, name, type, 0)) {
			xmlFreeNode(node);
			return (NULL);
		}
		/* attr->tag = 0; */
		prop = *(props ++);
	}

	/* generate sub elements for isns attributes of the object */
	i = 0;
	while (i < NUM_OF_ATTRS[obj->type]) {
		attr = &obj->attrs[i ++];
		j = get_index_by_tag(attr->tag);
		if (j >= 0) {
			name = xmlTag[j];
			type = xmlType[j][0];
			if (!convert_attr2xml(node, attr, name, type, 1)) {
				xmlFreeNode(node);
				return (NULL);
			}
		}
	}

	return (node);
}

/*
 * ****************************************************************************
 *
 * xml_init_data:
 *	initialization of the xml data store.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_init_data(
)
{
#define	XML_PATH	"/etc/isns"
#define	XML_FILE_NAME	"/isnsdata.xml"
#define	XML_DOT_TMP	".tmp"
#define	XML_DOT_BAK	".bak"

	int fd;
	xmlDocPtr doc;
	xmlNodePtr root;

	int len;
	char *xml_path, *p = NULL;

	char *cwd = NULL;

	int has_bak = 0;

	/* cannot reset the xml file when server is running */
	if (xml_file != NULL) {
		return (1);
	}

	/* set the data store file name along with the backup */
	/* file name and temporary file name */
	len = strlen(data_store);
	if (len > 0) {
		xml_file = data_store;
		p = strdup(xml_file);
		xml_bak_file = (char *)malloc(len + 5);
		xml_tmp_file = (char *)malloc(len + 5);
		if (p != NULL &&
		    xml_bak_file != NULL &&
		    xml_tmp_file != NULL) {
			xml_path = dirname(p);
			(void) strcpy(xml_bak_file, xml_file);
			(void) strcat(xml_bak_file, XML_DOT_BAK);
			(void) strcpy(xml_tmp_file, xml_file);
			(void) strcat(xml_tmp_file, XML_DOT_TMP);
		} else {
			return (1);
		}
	} else {
		xml_path = XML_PATH;
		xml_file = XML_PATH XML_FILE_NAME;
		xml_bak_file = XML_PATH XML_FILE_NAME XML_DOT_BAK;
		xml_tmp_file = XML_PATH XML_FILE_NAME XML_DOT_TMP;
	}

	/* save current working directory */
	cwd = getcwd(NULL, MAXPATHLEN);
	if (cwd == NULL) {
		return (1);
	}
	/* check access permission on data store directory */
	if (chdir(xml_path) != 0) {
		if (errno == ENOENT) {
			if (mkdir(xml_path, S_IRWXU) != 0 ||
			    chdir(xml_path) != 0) {
				return (1);
			}
		} else {
			return (1);
		}
	}
	/* go back to original working directory */
	(void) chdir(cwd);
	free(cwd);
	free(p);

	/* do not keep blank spaces */
	(void) xmlKeepBlanksDefault(0);

	/* remove the tmp file if it exists */
	if (access(xml_tmp_file, F_OK) == 0) {
		(void) remove(xml_tmp_file);
	}

	/* test if we can write the bak file */
	fd = open(xml_bak_file, O_RDWR);
	if (fd == -1) {
		fd = open(xml_bak_file, O_RDWR | O_CREAT,
		    S_IRUSR | S_IWUSR);
		if (fd == -1) {
			return (1);
		} else {
			(void) close(fd);
			(void) remove(xml_bak_file);
		}
	} else {
		has_bak = 1;
		(void) close(fd);
	}

	/* Test if we have the data store file, create an empty */
	/* data store if we do not have the data store file and */
	/* the backup data store. */
	fd = open(xml_file, O_RDWR);
	if (fd == -1) {
		if (has_bak == 0) {
			doc = xmlNewDoc(BAD_CAST "1.0");
			root = xmlNewNode(NULL, xml_root[0]);
			if (doc != NULL &&
			    root != NULL &&
			    xmlSetProp(root, xml_root[1], xml_root[2]) !=
			    NULL &&
			    xmlSetProp(root, xml_root[3], xml_root[4]) !=
			    NULL) {
				(void) xmlDocSetRootElement(doc, root);
				if (xmlSaveFormatFile(xml_file, doc, 1) == -1) {
					xmlFreeDoc(doc);
					return (-1);
				}
				xmlFreeDoc(doc);
			} else {
				if (doc != NULL) {
					xmlFreeDoc(doc);
				}
				if (root != NULL) {
					xmlFreeNode(root);
				}
				return (1);
			}
		} else {
			isnslog(LOG_WARNING, "get_xml_doc",
			    "initializing with backup data");
			if (rename(xml_bak_file, xml_file) != 0) {
				return (1);
			}
		}
	} else {
		(void) close(fd);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * xml_load_obj:
 *	load an isns object from the xml data store.
 *
 * p - the pointer of current xml node.
 * objp - the pointer of the object for returning.
 * level - the direction of xml parsing for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_load_obj(
	void **p,
	isns_obj_t **objp,
	uchar_t *level
)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = (xmlNodePtr)*p;
	int ec = 0;

	*objp = NULL;

	if (node == NULL) {
		*level = '^';
		ec = get_xml_doc(&doc);
		if (doc == NULL) {
			return (ec);
		}
		node = xmlDocGetRootElement(doc);
		if (node != NULL) {
			node = node->children;
		}
	} else if (node->children != NULL) {
		*level = '>';
		node = node->children;
	} else if (node->next != NULL) {
		*level = 'v';
		node = node->next;
	} else {
		*level = 'v';
		while (node != NULL && node->next == NULL) {
			if (node->type == XML_ELEMENT_NODE) {
				*level = '<';
			}
			node = node->parent;
		}
		if (node != NULL) {
			node = node->next;
		}
	}

	/* there is a node, parse it */
	if (node) {
		ec = parse_xml_obj(&node, objp);
		*p = (void *)node;
	}

	if (ec == 0 && *objp != NULL) {
		ec = update_deref_obj(*objp);
		if (ec != 0) {
			free_object(*objp);
			*objp = NULL;
		}
	}

	/* no object available, close the xml doc */
	if (*objp == NULL) {
		(void) close_xml_doc();
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_add_obj:
 *	add an isns object to the xml data store.
 *
 * obj - the object being added.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_add_obj(
	const isns_obj_t *obj
)
{
	int ec = 0;

	xmlDocPtr doc;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr node, prev;
	xmlNodePtr candidate;

	uint32_t puid, parent_type;

	int i;

	/* get the xml doc */
	ec = get_xml_doc(&doc);
	if (doc == NULL) {
		goto add_done;
	}

	/* create the candidate node */
	candidate = make_xml_node(obj);
	if (candidate == NULL) {
		ec = ISNS_RSP_INTERNAL_ERROR;
		goto add_done;
	}

	/* locate the position */
	parent_type = TYPE_OF_PARENT[obj->type];
	if (parent_type > 0) {
		puid = get_parent_uid(obj);
		ec = locate_xml_node(doc, parent_type, puid,
		    &node, &context, &result);
	} else {
		node = xmlDocGetRootElement(doc);
	}

	/* cannot locate the point for inserting the node */
	if (node == NULL) {
		xmlFreeNode(candidate);
		ec = ISNS_RSP_INTERNAL_ERROR;
		goto add_done;
	}

	/* add it with the apporiate child order */
	if (node->children) {
		node = node->children;
		while (node) {
			if (node->type == XML_ELEMENT_NODE) {
				i = get_index_by_name(node->name);
				ASSERT(i >= 0);
				if (xmlType[i][0] == 'o' &&
				    OBJ_DTD_ORDER[xmlArg1[i]] >=
				    OBJ_DTD_ORDER[obj->type]) {
					break;
				}
			}
			prev = node;
			node = node->next;
		}
		if (node == NULL) {
			node = xmlAddNextSibling(prev, candidate);
		} else {
			node = xmlAddPrevSibling(node, candidate);
		}
	} else {
		node = xmlAddChild(node, candidate);
	}

	if (node == NULL) {
		/* Failed, free the candidate node. */
		xmlFreeNode(candidate);
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

add_done:
	if (result) {
		xmlXPathFreeObject(result);
	}
	if (context) {
		xmlXPathFreeContext(context);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_modify_obj:
 *	modify an isns object in the xml data store.
 *
 * obj - the new object.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_modify_obj(
	const isns_obj_t *obj
)
{
	int ec = 0;
	xmlDocPtr doc;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr node, child;
	const char *props;
	char prop;
	int prop_id;
	int prop_tag;
	const xmlChar *name;
	unsigned char type;
	const isns_attr_t *attr;
	int i, j, k;
	int make_child;

	/* get the doc pointer */
	ec = get_xml_doc(&doc);
	if (doc == NULL) {
		return (ec);
	}

	/* locate the node for the object */
	i = get_index_by_otype(obj->type);
	ASSERT(i >= 0);
	prop = xmlArg2[i] - 'a';
	prop_id = xmlPropID[prop];
	attr = &obj->attrs[prop_id];
	ec = locate_xml_node(doc,
	    obj->type,
	    attr->value.ui,
	    &node, &context, &result);

	/* modify it */
	if (node != NULL) {
		props = &xmlType[i][1];
		prop = *(props ++);
		while (prop >= 'a' && prop <= 'z') {
			prop -= 'a';
			prop_id = xmlPropID[prop];
			prop_tag = xmlPropTag[prop];
			attr = &obj->attrs[prop_id];
			/* no need to update the key attributes, skip it. */
			/* btw, dd and dd-set names are non-key attributes. */
			if (prop_tag == ISNS_DD_NAME_ATTR_ID ||
			    prop_tag == ISNS_DD_SET_NAME_ATTR_ID) {
				name = xmlPropName[prop];
				type = xmlPropType[prop];
				if (!convert_attr2xml(node,
				    attr, name, type, 4)) {
					ec = ISNS_RSP_INTERNAL_ERROR;
					goto modify_done;
				}
			}
			/* attr->tag = 0; */
			prop = *(props ++);
		}
		/* set the child */
		child = node->children;
		if (child == NULL) {
			make_child = 1;
		} else {
			make_child = 0;
		}
		for (i = 0; i < NUM_OF_ATTRS[obj->type]; i++) {
			attr = &obj->attrs[i];
			j = get_index_by_tag(attr->tag);
			if (j < 0) {
				continue;
			}
			name = xmlTag[j];
			type = xmlType[j][0];
			if (make_child == 1) {
				/* make a child node */
				if (!convert_attr2xml(node, attr,
				    name, type, 1)) {
					ec = ISNS_RSP_INTERNAL_ERROR;
					goto modify_done;
				}
				continue;
			}
			while (child) {
				if (child->type == XML_ELEMENT_NODE) {
					k = get_index_by_name(child->name);
					ASSERT(k >= 0);
					if (xmlType[k][0] == 'o' ||
					    xmlType[k][0] == 'a' ||
					    xmlArg1[k] > attr->tag) {
						if (!convert_attr2xml(child,
						    attr, name, type, 2)) {
							/* internal error */
							ec = 11;
							goto modify_done;
						}
						break;
					} else if (xmlArg1[k] == attr->tag) {
						/* replace content */
						if (!convert_attr2xml(child,
						    attr, name, type, 3)) {
							/* internal error */
							ec = 11;
							goto modify_done;
						}
						break;
					}
				}
				child = child->next;
			}
			if (child == NULL) {
				/* make a child node */
				if (!convert_attr2xml(node, attr,
				    name, type, 1)) {
					ec = ISNS_RSP_INTERNAL_ERROR;
					goto modify_done;
				}
			}
		}
	} else {
		/* This case is for registering a node which has */
		/* membership in one or more non-default DD(s). */
		ec = xml_add_obj(obj);
	}

modify_done:
	if (result) {
		xmlXPathFreeObject(result);
	}
	if (context) {
		xmlXPathFreeContext(context);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_delete_obj:
 *	delete an isns object from the xml data store.
 *
 * obj - the object being deleted.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_delete_obj(
	const isns_obj_t *obj
)
{
	int ec = 0;
	xmlDocPtr doc;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr node;

	isns_type_t otype;
	uint32_t uid;

	/* get the xml doc */
	ec = get_xml_doc(&doc);
	if (doc == NULL) {
		return (ec);
	}

	otype = obj->type;
#ifdef WRITE_DATA_ASYNC
	/* it is a thin clone */
	uid = obj->attrs[0].value.ui;
#else
	uid = get_obj_uid(obj);
#endif

	/* locate the object */
	ec = locate_xml_node(doc,
	    otype,
	    uid,
	    &node, &context, &result);

	/* destroy it */
	if (node) {
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}

	if (result) {
		xmlXPathFreeObject(result);
	}
	if (context) {
		xmlXPathFreeContext(context);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_delete_assoc:
 *	delete a DD or DD-set membership from the xml data store.
 *
 * assoc - the membership being deleted.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_delete_assoc(
	const isns_obj_t *assoc
)
{
	int ec = 0;
	xmlDocPtr doc;
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr node;

	uint32_t puid, parent_type;
	uint32_t uid, match_uid;

	char prop;
	const xmlChar *prop_name;
	xmlChar *prop_value;
	int i;

	/* get the xml doc */
	ec = get_xml_doc(&doc);
	if (doc == NULL) {
		return (ec);
	}

	/* get the container object UID */
	parent_type = TYPE_OF_PARENT[assoc->type];
	ASSERT(parent_type != 0);
	puid = get_parent_uid(assoc);
	ASSERT(puid != 0);

	/* get the member object UID */
	i = get_index_by_otype(assoc->type);
	prop = xmlArg2[i] - 'a';
	prop_name = xmlPropName[prop];
	match_uid = assoc->attrs[UID_ATTR_INDEX[assoc->type]].value.ui;

	/* locate the container object */
	ec = locate_xml_node(doc, parent_type, puid,
	    &node, &context, &result);

	/* get the membership nodes */
	if (node != NULL) {
		node = node->children;
	}

	/* get the matching membership node */
	while (node) {
		if (node->type == XML_ELEMENT_NODE) {
			i = get_index_by_name(node->name);
			ASSERT(i >= 0);
			if (xmlType[i][0] == 'o' &&
			    xmlArg1[i] == assoc->type) {
				prop_value = xmlGetProp(node, prop_name);
				if (prop_value) {
					uid = atoi((const char *)prop_value);
					xmlFree(prop_value);
					if (uid == match_uid) {
						break;
					}
				}
			}
		}
		node = node->next;
	}

	/* destroy it */
	if (node) {
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}

	if (result) {
		xmlXPathFreeObject(result);
	}
	if (context) {
		xmlXPathFreeContext(context);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_update_commit:
 *	backup the current written file and commit all updates from
 *	the xml doc to the written file.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
static int
xml_update_commit(
)
{
	int ec = 0;

	if (xml_doc) {
		/* write to tmp file */
		if (xmlSaveFormatFile(xml_tmp_file, xml_doc, 1) == -1 ||
		    /* backup the current file */
		    rename(xml_file, xml_bak_file) != 0 ||
		    /* rename the tmp file to the current file */
		    rename(xml_tmp_file, xml_file) != 0) {
			/* failed saving file */
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
		/* close the xml_doc */
		xmlFreeDoc(xml_doc);
		xml_doc = NULL;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * xml_update_retreat:
 *	ignore all of updates in the xml doc.
 *
 * return - 0: always successful.
 *
 * ****************************************************************************
 */
static int
xml_update_retreat(
)
{
	if (xml_doc) {
		/* close the xml_doc */
		xmlFreeDoc(xml_doc);
		xml_doc = NULL;
	}

	return (0);
}
