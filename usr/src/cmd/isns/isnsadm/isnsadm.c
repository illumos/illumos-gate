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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * isnsadm.c : isnsadm CL
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <devid.h>
#include <fcntl.h>
#include <door.h>
#include <errno.h>
#include <strings.h>
#include <libscf.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/tree.h>
#include <wchar.h>
#include <locale.h>
#include "isns_mgmt.h"
#include "isns_utils.h"
#include "isns_protocol.h"
#include "cmdparse.h"
#include "isnsadm.h"

/* object functions per subcommand */
static int list_node_func(int, char **, cmdOptions_t *, void *);
static int list_dd_func(int, char **, cmdOptions_t *, void *);
static int list_ddset_func(int, char **, cmdOptions_t *, void *);
static int add_node_func(int, char **, cmdOptions_t *, void *);
static int add_dd_func(int, char **, cmdOptions_t *, void *);
static int delete_dd_func(int, char **, cmdOptions_t *, void *);
static int delete_ddset_func(int, char **, cmdOptions_t *, void *);
static int create_dd_func(int, char **, cmdOptions_t *, void *);
static int create_ddset_func(int, char **, cmdOptions_t *, void *);
static int remove_node_func(int, char **, cmdOptions_t *, void *);
static int remove_dd_func(int, char **, cmdOptions_t *, void *);
static int modify_dd_func(int, char **, cmdOptions_t *, void *);
static int modify_ddset_func(int, char **, cmdOptions_t *, void *);
static int enable_ddset_func(int, char **, cmdOptions_t *, void *);
static int disable_ddset_func(int, char **, cmdOptions_t *, void *);
static int show_config_func(int, char **, cmdOptions_t *, void *);
static int i_enableddset(int, char **, boolean_t);
static xmlTextReaderPtr lookup_next_matching_elem(xmlTextReaderPtr, int *,
	const char *, const char *);
static int handle_association_info(xmlChar *, association_t);
static int process_result_response(xmlChar *, int obj);
static int process_get_assoc_response(xmlChar *, association_t);
static int process_get_response(object_type, xmlChar *, uint32_t);
static int cvt_enumerate_rsp_to_get_req(xmlChar *, xmlChar **, object_type,
	uint32_t);
static int build_get_xml_doc(int, char **, object_type, xmlChar **);
static int build_delete_xml_doc(int, char **, object_type, char *, xmlChar **);
static int build_create_xml_doc(int, char **, object_type, char *, xmlChar **);
static int build_modify_xml_doc(int, char **, object_type, boolean_t,
	xmlChar **);
static int build_rename_xml_doc(char *, object_type, uint32_t, xmlChar **);
static int build_assoc_xml_doc(xmlChar *, association_t, xmlChar **);
static int build_assoc_xml_doc(xmlChar *, association_t, xmlChar **);
static int build_enumerate_xml_doc(object_type, xmlChar **);

#define	NEW_XMLARGV(old, n) (xmlChar **)realloc((xmlChar *)old, \
	(unsigned)(n+2) * sizeof (xmlChar *))

#define	XML_SFREE(x)	(((x) != NULL) ? (xmlFree(x), (x) = NULL) : (void *)0)

#define	VERSION_STRING_MAX_LEN	10

#define	OPTIONSTRING_NAME	"name"
#define	OPTIONSTRING_DDNAME	"Discovery Domain name"
#define	OPTIONSTRING_DDSETNAME	"Discovery Domain Set name"
#define	OPTIONSTRING_TARGET	"target"
#define	OPTIONSTRING_INITIATOR	"initiator"
#define	OPTIONSTRING_VERBOSE	"verbose"

#define	VERBOSE		0x00000001
#define	INITIATOR_ONLY	0x00000010
#define	TARGET_ONLY	0x00000100

#if LIBXML_VERSION >= 20904
#define	XMLSTRING_CAST (const char *)
#else
#define	XMLSTRING_CAST (const xmlChar *)
#endif

/* object table based on definitions in isns_mgmt.h. */
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
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
static char *ISNS_FMRI = "network/isns_server:default";

/*
 * Add new options here
 */

/* tables set up based on cmdparse instructions */
optionTbl_t longOptions[] = {
	{"target", no_arg, 't', OPTIONSTRING_TARGET},
	{"initiator", no_arg, 'i', OPTIONSTRING_INITIATOR},
	{"verbose", no_arg, 'v', OPTIONSTRING_VERBOSE},
	{"name", required_arg, 'n', OPTIONSTRING_NAME},
	{"dd", required_arg, 'd', OPTIONSTRING_DDNAME},
	{"dd-set", required_arg, 's', OPTIONSTRING_DDSETNAME},
	{NULL, 0, 0, 0}
};


/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
	{"list-node", LISTNODE, list_node_func, "itv", B_FALSE, NULL,
		OPERAND_OPTIONAL_MULTIPLE, "node-name"},
	{"list-dd", LISTDD, list_dd_func, "v", B_FALSE, NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPTIONSTRING_DDNAME},
	{"list-dd-set", LISTDDSET, list_ddset_func, "v", B_FALSE, NULL,
		OPERAND_OPTIONAL_MULTIPLE, OPTIONSTRING_DDSETNAME},
	{"create-dd", CREATEDD, create_dd_func, NULL, B_FALSE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDNAME},
	{"create-dd-set", CREATEDDSET, create_ddset_func, NULL, B_FALSE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDSETNAME},
	{"delete-dd", DELETEDD, delete_dd_func, NULL, B_FALSE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDNAME},
	{"delete-dd-set", DELETEDDSET, delete_ddset_func, NULL, B_FALSE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDSETNAME},
	{"add-node", ADDNODE, add_node_func, "d", B_TRUE, NULL,
		OPERAND_MANDATORY_MULTIPLE, "node-name"},
	{"add-dd", ADDDD, add_dd_func, "s", B_TRUE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDNAME},
	{"remove-node", REMOVENODE, remove_node_func, "d", B_TRUE, NULL,
		OPERAND_MANDATORY_MULTIPLE, "node-name"},
	{"remove-dd", REMOVEDD, remove_dd_func, "s", B_TRUE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDNAME},
	{"modify-dd", MODIFYDD, modify_dd_func, "n", B_TRUE, NULL,
		OPERAND_MANDATORY_SINGLE, OPTIONSTRING_NAME},
	{"modify-dd-set", MODIFYDDSET, modify_ddset_func, "n", B_TRUE, NULL,
		OPERAND_MANDATORY_SINGLE, OPTIONSTRING_NAME},
	{"enable-dd-set", ENABLEDDSET, enable_ddset_func, NULL, B_FALSE, NULL,
		OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDSETNAME},
	{"disable-dd-set", DISABLEDDSET, disable_ddset_func, NULL, B_FALSE,
		NULL, OPERAND_MANDATORY_MULTIPLE, OPTIONSTRING_DDSETNAME},
	{"show-config", SHOWCONFIG, show_config_func, NULL, B_FALSE, NULL,
		OPERAND_NONE, NULL},
	{NULL, 0, NULL, NULL, 0, NULL, 0, NULL}
};

/*
 * ****************************************************************************
 *
 * check_door_error
 *
 * input:
 *  errno from the door call.
 *
 * Returns:
 *  either door error or smf service error.
 *
 * ****************************************************************************
 */
static int
check_door_error(int door_err, int err)
{
	char	*state = NULL;
	int	ret;

	if (((state = smf_get_state(ISNS_FMRI)) != NULL) &&
	    (strcmp(state, SCF_STATE_STRING_ONLINE) != 0)) {
		ret = ERROR_ISNS_SMF_SERVICE_NOT_ONLINE;
	} else {
	    (void) fprintf(stderr, "%s\n",
		(door_err == ERROR_DOOR_CALL_FAILED) ?
		getTextMessage(ERROR_DOOR_CALL_FAILED) :
		getTextMessage(ERROR_DOOR_OPEN_FAILED));
	    (void) fprintf(stderr, "\terrno: %s\n", strerror(err));
	    ret = door_err;
	}

	if (state) free(state);

	return (ret);
}

/*
 * ****************************************************************************
 *
 * lookup an element based on the element name.
 *
 * reader	- current xmlReaderReadPtr
 * m_falg	- indicate lookup result
 * elem		- name of element to look up.
 * endelem	- name of end element to look up.
 *
 * ****************************************************************************
 */
static	xmlTextReaderPtr
lookup_next_matching_elem(xmlTextReaderPtr reader, int *m_flag,
	const char *elem, const char *endelem)
{

	if (reader == NULL) {
	    *m_flag = NO_MATCH;
	    return (NULL);
	}

	do {
	/*
	 * if (xmlTextReaderName(reader) != NULL) {
	 * 	printf("%s ", xmlTextReaderName(reader));
	 * }
	 * printf("%d %d %d\n",
	 * xmlTextReaderDepth(reader),
	 * xmlTextReaderNodeType(reader),
	 * xmlTextReaderIsEmptyElement(reader));
	 */
		/*
		 * if match with elem, return the reader with READER_MATCH flag.
		 * if match with end elem, return the reader wtih
		 * END_READER_MATCH flag.
		 */
	    if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
		if (XMLNCMP(reader, elem) == 0) {
		    *m_flag = READER_MATCH;
		    return (reader);
		}
	    } else if (xmlTextReaderNodeType(reader) ==
		XML_READER_TYPE_END_ELEMENT) {
		if (XMLNCMP(reader, endelem) == 0) {
		    *m_flag = END_READER_MATCH;
		    return (reader);
		}
	    }
	} while (xmlTextReaderRead(reader) == 1);

	*m_flag = NO_MATCH;
	return (NULL);
}

/*
 * ****************************************************************************
 *
 * Routine for getAssociated operation
 *	Construct association request  based on the name and calls door
 *	interface.
 *
 * name		- name attributes of an object for getting an association
 * assoc	- association type
 *
 * ****************************************************************************
 */
static int
handle_association_info(xmlChar *name, association_t assoc)
{

	xmlChar *doc;
	door_arg_t darg;
	msg_code_t ret;
	int fd;

	if ((ret = build_assoc_xml_doc(name, assoc, &doc)) != 0) {
	    return (ret);
	}

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	(void) bzero(&darg, sizeof (darg));
	bzero(&darg, sizeof (darg));
	darg.data_ptr = (char *)doc;
	darg.data_size = xmlStrlen(doc) + 1;
	darg.rbuf = NULL;
	darg.rsize = 0;
	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	if ((ret = process_get_assoc_response((xmlChar *)darg.rbuf,
	    assoc)) != 0) {
	/*
	 * door frame work allocated a buffer when the date lager
	 * that rbuf. indicate if munmap is required on rbuf.
	 */
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);

	(void) close(fd);
	(void) xmlFree(doc);

	return (0);
}

/*
 * ****************************************************************************
 *
 * process_error_status
 *	The routine process non 0 status and print out error message.
 *
 * status	- status code
 * reader	- reader that points to the message element.
 *
 * ****************************************************************************
 */
static void
print_error_status(int status, int obj, xmlTextReaderPtr reader)
{
	int m_flag = 0;

	switch (status) {
	case ISNS_RSP_BUSY:
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_SERVER_BUSY));
	    break;
	case ISNS_RSP_INTERNAL_ERROR:
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_SERVER_INTERNAL_ERROR));
	    break;
	case ISNS_RSP_OPTION_NOT_UNDERSTOOD:
	    if ((obj == DiscoveryDomain) ||
		(obj == DiscoveryDomainMember)) {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DD));
	    } else {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DDSET));
	    }
	    break;
	case PARTIAL_FAILURE:
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_PARTIAL_FAILURE));
	    break;
	case ERR_NO_SUCH_ASSOCIATION:
	    if ((obj == DiscoveryDomain) ||
		(obj == DiscoveryDomainMember)) {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DDMEMBER_NOT_FOUND));
	    } else {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DDSETMEMBER_NOT_FOUND));
	    }
	    break;
	case ERR_ALREADY_ASSOCIATED:
	    if ((obj == DiscoveryDomain) ||
		(obj == DiscoveryDomainMember)) {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DDMEMBER_ALREADY_EXIST));
	    } else {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DDSETMEMBER_ALREADY_EXIST));
	    }
	    break;
	case ERR_NAME_IN_USE:
	    if ((obj == DiscoveryDomain) ||
		(obj == DiscoveryDomainMember)) {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DD_NAME_IN_USE));
	    } else {
		(void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_DDSET_NAME_IN_USE));
	    }
	    break;
	default:
	    reader = lookup_next_matching_elem(reader, &m_flag,
		MESSAGEELEMENT, RESULTELEMENT);
	    if (m_flag == READER_MATCH) {
		(void) xmlTextReaderRead(reader);
		(void) fprintf(stderr, "Error: %s\n",
			(const char *) xmlTextReaderConstValue(reader));
	    } else {
		(void) fprintf(stderr, "Error: %s\n",
		getTextMessage(ERROR_XML_MESSAGE_ELEM_NOT_FOUND));
	    }
	}
}

/*
 * ****************************************************************************
 *
 * print_partial_failure_info
 *	The routine prints partial failure info.
 *
 * status	- status code
 * reader	- reader that points to the message element.
 *
 * ****************************************************************************
 */
static void
print_partial_failure_info(xmlChar *doc)
{
	xmlChar expr[ISNS_MAX_LABEL_LEN + 13];
	xmlDocPtr x_doc;
	xmlXPathContextPtr ctext = NULL;
	xmlXPathObjectPtr xpath_obj = NULL;
	xmlNodeSetPtr r_nodes = NULL;
	xmlAttrPtr attr = NULL;
	int i, cnt, obj = 0;

	if ((x_doc = xmlParseMemory((const char *)doc, xmlStrlen(doc))) ==
	    NULL) {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_NO_ADDITIONAL_PARTIAL_FAILIRE_INFO));
	}

	ctext = xmlXPathNewContext(x_doc);
	if (ctext == NULL) {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_NO_ADDITIONAL_PARTIAL_FAILIRE_INFO));
	}

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
	}

	if (obj == 0) {
	    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_NO_ADDITIONAL_PARTIAL_FAILIRE_INFO));
	}

	switch (obj) {
	    case DiscoveryDomainMember:
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				(void) fprintf(stderr, "DD Name: %s\t",
				xmlNodeGetContent(attr->children));
			}
			if (xmlStrncmp(attr->name, (xmlChar *)NODENAMEATTR,
			    xmlStrlen((xmlChar *)NODENAMEATTR)) == 0) {
				(void) fprintf(stderr, "Node Name: %s\t",
				xmlNodeGetContent(attr->children));
			}
		    }
		    (void) fprintf(stderr, "\n");
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case DiscoveryDomainSetMember:
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if (xmlStrncmp(attr->name, (xmlChar *)DDSETNAMEATTR,
			    xmlStrlen((xmlChar *)DDNAMEATTR)) == 0) {
				(void) fprintf(stderr, "DD Set Name: %s\t",
				xmlNodeGetContent(attr->children));
			}
			if (xmlStrncmp(attr->name, (xmlChar *)DDNAMEATTR,
			    xmlStrlen((xmlChar *)NODENAMEATTR)) == 0) {
				(void) fprintf(stderr, "DD Name: %s\t",
				xmlNodeGetContent(attr->children));
			}
		    }
		    (void) fprintf(stderr, "\n");
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	    case Node:
	    case DiscoveryDomain:
	    case DiscoveryDomainSet:
		r_nodes = xpath_obj->nodesetval;
		cnt = r_nodes->nodeNr;
		for (i = 0; i < cnt; i++) {
		    attr = r_nodes->nodeTab[i]->properties;
		    for (; attr != NULL; attr = attr->next) {
			if ((xmlStrncmp(attr->name, (xmlChar *)NAMEATTR,
			    xmlStrlen((xmlChar *)NAMEATTR))) == 0) {
				(void) fprintf(stderr, "Object Name: %s\n",
				xmlNodeGetContent(attr->children));
			}
		    }
		}
		if (xpath_obj) xmlXPathFreeObject(xpath_obj);
		break;
	}
}

/*
 * ****************************************************************************
 *
 * process_result_response
 *	The routine process association data based on the association type.
 *
 * doc		- result
 * obj		- associated object type
 *
 * ****************************************************************************
 */
static int
process_result_response(xmlChar *doc, int obj)
{
	xmlTextReaderPtr reader;
	int m_flag = 0, status;

	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory((const char *)doc,
	    xmlStrlen(doc), NULL, NULL, 0)) == NULL) {
		return (ERROR_XML_READER_NULL);
	}

	/* if status is 0, continue on.  Otherwise return an error. */
	if (reader = lookup_next_matching_elem(reader, &m_flag, STATUSELEMENT,
	    RESULTELEMENT)) {
	    if (m_flag == READER_MATCH) {
		if (xmlTextReaderRead(reader) == 1) {
		    status =
		    atoi((const char *)xmlTextReaderConstValue(reader));
		    if (status != 0) {
			print_error_status(status, obj, reader);
			(void) xmlTextReaderClose(reader);
			(void) xmlFreeTextReader(reader);
			if (status == PARTIAL_FAILURE) {
			    print_partial_failure_info(doc);
			}
			return (status);
		    }
		} else {
		    (void) xmlTextReaderClose(reader);
		    (void) xmlFreeTextReader(reader);
		    return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
		}
	    } else {
		(void) xmlTextReaderClose(reader);
		(void) xmlFreeTextReader(reader);
		return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
	    }
	} else {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_XML_READER_NULL));
	    return (ERROR_XML_READER_NULL);
	}

	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);
	return (0);
}

/*
 * ****************************************************************************
 *
 * process_get_assoc_response
 *	The routine process association data based on the association type.
 *
 * doc		- association data
 * assoc	- associatiion type
 *
 * ****************************************************************************
 */
static int
process_get_assoc_response(xmlChar *doc, association_t assoc)
{
	xmlTextReaderPtr reader;
	xmlChar *ddsname, *ddname, *nodename;
	wchar_t wc_name[ISNS_MAX_NAME_LEN];
	int m_flag = 0, h_printed = 0, status;

	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory((const char *)doc,
			xmlStrlen(doc), NULL, NULL, 0)) == NULL) {
	    return (ERROR_XML_READER_NULL);
	}

	/* if status is 0, continue on.  Otherwise return an error. */
	if (reader = lookup_next_matching_elem(reader, &m_flag, STATUSELEMENT,
	    RESULTELEMENT)) {
	    if (m_flag == READER_MATCH) {
		if (xmlTextReaderRead(reader) == 1) {
		    status =
		    atoi((const char *)xmlTextReaderConstValue(reader));
		    if ((status != 0) && (status != PARTIAL_SUCCESS)) {
			/* not an error */
			if ((status !=  ERR_NO_SUCH_ASSOCIATION) &&
			    (status !=  ERR_NO_ASSOCIATED_DD_FOUND) &&
			    (status !=  ERR_NO_ASSOCIATED_DDSET_FOUND)) {
			    (void) xmlTextReaderClose(reader);
			    (void) xmlFreeTextReader(reader);
			    return (0);
			} else {
			    print_error_status(status,
				((assoc == node_to_dd) || (dd_to_node)) ?
				DiscoveryDomain : DiscoveryDomainSet, reader);
			    (void) xmlTextReaderClose(reader);
			    (void) xmlFreeTextReader(reader);
			    return (status);
			}
		    }
		} else {
		    (void) xmlTextReaderClose(reader);
		    (void) xmlFreeTextReader(reader);
		    return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
		}
	    } else {
		return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
	    }
	} else {
	    return (ERROR_XML_READER_NULL);
	}

	m_flag = 0;

	switch (assoc) {
	    case node_to_dd:
		/* process DD elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDOBJECTMEMBER, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    } else if (m_flag == READER_MATCH) {
			if ((ddname = (xmlTextReaderGetAttribute(reader,
			    (const xmlChar *)DDNAMEATTR))) != NULL) {
			    if (mbstowcs(wc_name, (const char *)ddname,
				ISNS_MAX_NAME_LEN) == (size_t)-1) {
				(void) wcscpy(wc_name, L"-");
			    }
			    if (h_printed) {
				(void) printf("\tDD Name: %ws\n", wc_name);
			    } else {
				(void) printf("\tDD Name: %ws\n", wc_name);
				h_printed = 1;
			    }
			    xmlFree(ddname);
			} else {
			    if (h_printed) {
				(void) printf("\t         %s\n", "-");
			    } else {
				(void) printf("\tDD Name: %s\n", "-");
				h_printed = 1;
			    }
			}
		    }
		    m_flag = 0;
		    (void) xmlTextReaderRead(reader);
		}
	    break;
	case dd_to_node:
		/* process the DiscoveryDoamin elements */
	    while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDOBJECTMEMBER, ISNSRESPONSE)) {
		if (m_flag == END_READER_MATCH) {
		    (void) xmlTextReaderNext(reader);
		    break;
		} else if (m_flag == READER_MATCH) {
		    if ((nodename = (xmlTextReaderGetAttribute(reader,
			    (const xmlChar *)NODENAMEATTR))) != NULL) {
			if (mbstowcs(wc_name, (const char *)nodename,
			    ISNS_MAX_NAME_LEN) == (size_t)-1) {
			    (void) wcscpy(wc_name, L"-");
			}
			(void) printf("\tiSCSI name: %ws\n", wc_name);
			xmlFree(nodename);
		    } else {
			(void) printf("\tiSCSI name: %s\n", "-");
		    }
		}
		m_flag = 0;
		(void) xmlTextReaderRead(reader);
	    }
	    break;
	case dd_to_ddset:
		/* process the DiscoveryDoaminSet elements */
	    while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDSETOBJECTMEMBER, ISNSRESPONSE)) {
		if (m_flag == END_READER_MATCH) {
		    (void) xmlTextReaderNext(reader);
		    break;
		} else if (m_flag == READER_MATCH) {
		    if ((ddsname = (xmlTextReaderGetAttribute(reader,
			(const xmlChar *)DDSETNAMEATTR))) != NULL) {
			if (mbstowcs(wc_name, (const char *)ddsname,
			    ISNS_MAX_NAME_LEN) == (size_t)-1) {
			    (void) wcscpy(wc_name, L"-");
			}
			if (h_printed) {
			    (void) printf("\t           %ws\n", wc_name);
			} else {
			    (void) printf("\tDD set(s): %ws\n", wc_name);
			    h_printed = 1;
			}
			xmlFree(ddsname);
		    } else {
			(void) printf("\tDD set(s): %s\n", "-");
		    }
		}
		m_flag = 0;
		(void) xmlTextReaderRead(reader);
	    }
	    break;
	case ddset_to_dd:
		/* process the DiscoveryDoaminSet elements */
	    while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDSETOBJECTMEMBER, ISNSRESPONSE)) {
		if (m_flag == END_READER_MATCH) {
		    (void) xmlTextReaderNext(reader);
		    break;
		} else if (m_flag == READER_MATCH) {
			if ((ddname = (xmlTextReaderGetAttribute(reader,
			    (const xmlChar *)DDNAMEATTR))) != NULL) {
			    if (mbstowcs(wc_name, (const char *)ddname,
				ISNS_MAX_NAME_LEN) == (size_t)-1) {
				(void) wcscpy(wc_name, L"-");
			    }
			    (void) printf("\tDD Name: %ws\n", wc_name);
			    xmlFree(ddname);
			} else {
			    (void) printf("\tDD Name: %s\n", "-");
			}
		}
		m_flag = 0;
		(void) xmlTextReaderRead(reader);
	    }
	    break;
	default:
	    (void) xmlTextReaderClose(reader);
	    (void) xmlFreeTextReader(reader);
	    return (UNKNOWN);
	}

	if (status == PARTIAL_SUCCESS) {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_PARTIAL_SUCCESS));
	}
	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);
	return (status);
}

/*
 * ****************************************************************************
 *
 * process_get_response :
 *	display data from the get response doc based on flag.
 *
 * obj		- object type
 * doc		- docuemet to process
 * flag		- options from the subcommand
 *
 * ****************************************************************************
 */
static int
process_get_response(object_type obj, xmlChar *doc, uint32_t flag)
{
	xmlTextReaderPtr reader;
	int m_flag = 0, ret = 0, status;
	xmlChar *name = NULL;
	wchar_t wc_name[ISNS_MAX_NAME_LEN];
	int tag_printed = 0;

	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory((const char *)doc,
	    xmlStrlen(doc), NULL, NULL, 0)) == NULL) {
		return (ERROR_XML_READER_NULL);
	}

	/* if status is 0, continue on.  Otherwise return an error. */
	if (reader = lookup_next_matching_elem(reader, &m_flag, STATUSELEMENT,
	    RESULTELEMENT)) {
	    if (m_flag == READER_MATCH) {
		if (xmlTextReaderRead(reader) == 1) {
		    status =
		    atoi((const char *)xmlTextReaderConstValue(reader));
		    if ((status != 0) && (status != PARTIAL_SUCCESS)) {
			print_error_status(status, obj, reader);
			(void) xmlTextReaderClose(reader);
			(void) xmlFreeTextReader(reader);
			return (status);
		    }
		} else {
		    (void) xmlTextReaderClose(reader);
		    (void) xmlFreeTextReader(reader);
		    return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
		}
	    } else {
		(void) xmlTextReaderClose(reader);
		(void) xmlFreeTextReader(reader);
		return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
	    }
	} else {
	    return (ERROR_XML_READER_NULL);
	}

	m_flag = 0;

	switch (obj) {
	    case Node:
		/* process the node elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    NODEOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			break;
		    }

		    /* check the type */
		    if ((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)TYPEATTR)) == 1) {
			if (((flag & TARGET_ONLY) == TARGET_ONLY) &&
			    (XMLNCMPVAL(reader, TARGETTYPE) != 0)) {
			    /* move to next node object. */
			    (void) xmlTextReaderMoveToElement(reader);
			    (void) xmlTextReaderNext(reader);
			    continue;
			}
			if (((flag & INITIATOR_ONLY) == INITIATOR_ONLY) &&
			    (XMLNCMPVAL(reader, INITIATORTYPE) != 0)) {
			    /* move to next node object. */
			    (void) xmlTextReaderMoveToElement(reader);
			    (void) xmlTextReaderNext(reader);
			    continue;
			}
		    } else {
			ret = ERROR_XML_TYPE_ATTR_NOT_FOUND;
			goto out;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			(const char *)xmlTextReaderConstValue(reader)) {
			if (mbstowcs(wc_name,
			    (const char *)xmlTextReaderConstValue(reader),
			    ISNS_MAX_NAME_LEN) == (size_t)-1) {
			    (void) wcscpy(wc_name, L"-");
			}
			if ((flag & VERBOSE) == VERBOSE) {
			    name = xmlTextReaderValue(reader);
			    (void) printf("iSCSI Name: %ws\n", wc_name);
			} else {
			    (void) printf("iSCSI Name: %ws\n", wc_name);
			}
		    } else {
			XML_SFREE(name);
			ret = ERROR_XML_TYPE_ATTR_NOT_FOUND;
			goto out;
		    }
		    if ((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)ALIASATTR)) == 1) {
			if (xmlStrcmp(xmlTextReaderConstValue(reader),
			    (xmlChar *)"") == 0) {
			    (void) printf("\tAlias: %s\n", "-");
			} else {
			    if (mbstowcs(wc_name,
				(const char *)xmlTextReaderConstValue(reader),
				ISNS_MAX_NAME_LEN) == (size_t)-1) {
				(void) wcscpy(wc_name, L"-");
			    }
			    (void) printf("\tAlias: %ws\n", wc_name);
			}
		    }

		    /* type attribute exist based on the previous checking. */
		    (void) xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)TYPEATTR);
		    (void) printf("\tType: %s\n",
			(const char *)xmlTextReaderConstValue(reader) ?
			(const char *)xmlTextReaderConstValue(reader) : "-");

		    if ((flag & VERBOSE) == VERBOSE) {
			/* print more details */
			m_flag = 0;
			/*
			 * No details for deregistered node.
			 * skip to next isns object.
			 */
			if ((reader = lookup_next_matching_elem(reader,
			    &m_flag, ENTITYID, ISNSOBJECT))) {
			    if (m_flag == READER_MATCH) {
				/* move to entity id value. */
				if ((xmlTextReaderRead(reader) == 1) &&
				    xmlTextReaderConstValue(reader)) {
				    if (mbstowcs(wc_name,
					(const char *)
					xmlTextReaderConstValue(reader),
					ISNS_MAX_NAME_LEN) == (size_t)-1) {
					(void) wcscpy(wc_name,
					    L"-");
				    }
				    (void) printf("\tNetwork Entity: %ws\n",
					wc_name);
				} else {
				    (void) printf("\tNework Entity: -\n");
				}
			    } else if (m_flag == END_READER_MATCH) {
				(void) xmlTextReaderRead(reader);
				XML_SFREE(name);
				continue;
			    }
			}

			/* print  portal info */
			m_flag = 0;
			while ((reader = lookup_next_matching_elem(reader,
			    &m_flag, IPADDR, NODEOBJECT))) {
			    if (m_flag == END_READER_MATCH) {
				(void) xmlTextReaderRead(reader);
				break;
			    }
			    /* move to the value of IP addr. */
			    if ((xmlTextReaderRead(reader) == 1) &&
				xmlTextReaderConstValue(reader)) {
				(void) printf("\tPortal: %s",
				xmlTextReaderConstValue(reader));
				/* get port number */
				m_flag = 0;
				if (reader = lookup_next_matching_elem(reader,
				    &m_flag, PORTNUMBER, UDPTCPPORT)) {
				    if ((xmlTextReaderRead(reader) == 1) &&
					xmlTextReaderConstValue(reader)) {
				    (void) printf(":%d\n",
					atoi((const char *)
					xmlTextReaderConstValue(reader)));
				    } else {
					(void) printf(":-\n");
				    }
				}
				m_flag = 0;
				if (reader = lookup_next_matching_elem(reader,
				    &m_flag, GROUPTAG, GROUPTAG)) {
				    if ((xmlTextReaderRead(reader) == 1) &&
					xmlTextReaderConstValue(reader)) {
				    (void) printf("\t\tPortal Group: %s\n",
					xmlTextReaderConstValue(reader));
				    } else {
					(void) printf(":-\n");
				    }
				}
			    }
			} /* Portal end */
			if ((ret = handle_association_info(name,
			    node_to_dd)) != 0) {
			    XML_SFREE(name);
			    goto out;
			}
		    } /* verbose end */
		    XML_SFREE(name);
		    (void) xmlTextReaderRead(reader);
		    m_flag = 0;
		} /* end for node while */
		break;
	    case DiscoveryDomain:
		/* process the DiscoveryDoamin elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			(name = xmlTextReaderValue(reader))) {
			if (mbstowcs(wc_name, (const char *)name,
			    ISNS_MAX_NAME_LEN) == (size_t)-1) {
			    (void) wcscpy(wc_name, L"-");
			}
			(void) printf("DD name: %ws\n", wc_name);
		    } else {
			ret = ERROR_XML_NAME_ATTR_NOT_FOUND;
			XML_SFREE(name);
			goto out;
		    }
		    if ((ret = handle_association_info(name, dd_to_ddset)) !=
			0) {
			XML_SFREE(name);
			goto out;
		    }
		    /* handle verbose */
		    if ((flag & VERBOSE) == VERBOSE) {
			if ((ret = handle_association_info(name,
			    dd_to_node)) != 0) {
			    XML_SFREE(name);
			    goto out;
			}
		    }
		    XML_SFREE(name);
		    m_flag = 0;
		}
		break;
	    case DiscoveryDomainSet:
		/* process the DiscoveryDoaminSet elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDSETOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			(const char *)xmlTextReaderConstValue(reader)) {
			if (mbstowcs(wc_name,
			    (const char *)xmlTextReaderConstValue(reader),
			    ISNS_MAX_NAME_LEN) == (size_t)-1) {
			    (void) wcscpy(wc_name, L"-");
			}
			if ((flag & VERBOSE) == VERBOSE) {
			    name = xmlTextReaderValue(reader);
			    (void) printf("DD Set name: %ws\n", wc_name);
			} else {
			    (void) printf("DD Set name: %ws\n", wc_name);
			}
		    } else {
			ret = ERROR_XML_NAME_ATTR_NOT_FOUND;
			XML_SFREE(name);
			goto out;
		    }
		    m_flag = 0;
		    if ((reader = lookup_next_matching_elem(reader,
			&m_flag, ENABLEDELEM, ISNSOBJECT))) {
			if (m_flag == READER_MATCH) {
			    /* move to entity id value. */
			    if ((xmlTextReaderRead(reader) == 1) &&
				(XMLNCMPVAL(reader, XMLTRUE) == 0)) {
				(void) printf("\tState: Enabled\n");
			    } else {
				(void) printf("\tState: Disabled\n");
			    }
			} else if (m_flag == END_READER_MATCH) {
			    (void) xmlTextReaderRead(reader);
			}
		    }

		    /* handle verbose */
		    if ((flag & VERBOSE) == VERBOSE) {
			if ((ret = handle_association_info(name,
			    ddset_to_dd)) != 0) {
			    XML_SFREE(name);
			    goto out;
			}
		    }
		    XML_SFREE(name);
		    m_flag = 0;
		}
		break;
	    case ServerConfig:
		/* process the DiscoveryDoaminSet elements */
		m_flag = 0;
		reader = lookup_next_matching_elem(reader, &m_flag,
		    ISNSSERVER, ISNSRESPONSE);
		if (m_flag == END_READER_MATCH) {
		    ret = ERROR_XML_ISNSSERVER_ELEM_NOT_FOUND;
		    goto out;
		}
		m_flag = 0;
		if ((reader = lookup_next_matching_elem(reader,
		    &m_flag, DATASTORELOCATION, ISNSRESPONSE))) {
		    if (m_flag == READER_MATCH) {
			(void) xmlTextReaderRead(reader);
			(void) printf("\tData Store Location: %s\n",
			(const char *)xmlTextReaderConstValue(reader) ?
			(const char *)xmlTextReaderConstValue(reader) : "-");
		    }
		}
		m_flag = 0;
		if ((reader = lookup_next_matching_elem(reader,
		    &m_flag, ESIRETRYTHRESHOLD, ISNSRESPONSE))) {
		    if (m_flag == READER_MATCH) {
			(void) xmlTextReaderRead(reader);
			(void) printf("\tEntity Status Inquiry Non-Response ");
			(void) printf("Threshold: %d\n",
			xmlTextReaderConstValue(reader) ?
			atoi((const char *)xmlTextReaderConstValue(reader))
			: 0);
		    }
		}
		m_flag = 0;
		if ((reader = lookup_next_matching_elem(reader,
		    &m_flag, MANAGEMENTSCNENABLED, ISNSRESPONSE))) {
		    if (m_flag == READER_MATCH) {
			(void) xmlTextReaderRead(reader);
			(void) printf("\tManagement SCN Enabled: %s\n",
			(XMLNCMPVAL(reader, XMLTRUE) == 0) ?
			"yes" : "no");
		    }
		}
		m_flag = 0;
		while ((reader = lookup_next_matching_elem(reader,
		    &m_flag, CONTROLNODENAME, ISNSSERVER))) {
		    if (m_flag == READER_MATCH) {
			if (!xmlTextReaderIsEmptyElement(reader)) {
			    (void) xmlTextReaderRead(reader);
			    if (mbstowcs(wc_name,
				(const char *)xmlTextReaderConstValue(reader),
				ISNS_MAX_NAME_LEN) == (size_t)-1) {
				(void) wcscpy(wc_name, L"-");
			    }
			    if (tag_printed) {
				if (xmlTextReaderConstValue(reader)) {
				    if (mbstowcs(wc_name,
					(const char *)
					xmlTextReaderConstValue(reader),
					ISNS_MAX_NAME_LEN) == (size_t)-1) {
					(void) wcscpy(wc_name, L"-");
				    }
				    (void) printf(
				    "\t                               %ws\n",
					wc_name);
				} else {
				    (void) printf(
				    "\t                               %s\n",
				    "-");
				}
			    } else {
				if (xmlTextReaderConstValue(reader)) {
				    if (mbstowcs(wc_name,
					(const char *)
					xmlTextReaderConstValue(reader),
					ISNS_MAX_NAME_LEN) == (size_t)-1) {
					(void) wcscpy(wc_name, L"-");
				    }
				    (void) printf(
				    "\tAuthorized Control Node Names: %ws\n",
					wc_name);
				} else {
				    (void) printf(
				    "\tAuthorized Control Node Names: %s\n",
				    "-");
				}
				tag_printed = 1;
			    }
			} else {
			    (void) printf(
				"\tAuthorized Control Node Names: %s\n", "-");
			    break;
			}
		    } else {
			break;
		    }
		}
		break;
	    default:
		ret = UNKNOWN;
	}

out:
	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);
	if (status == PARTIAL_SUCCESS) {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_PARTIAL_SUCCESS));
	    if (ret == 0) ret = status;
	}
	return (ret);

}

/*
 * ****************************************************************************
 *
 * cvt_enumerate_rsp_to_get_req:
 *	pull out object info from enumerate response and calls
 *	build_get_xml_doc based on object type.
 *
 * doc		- enumerate resonse from the server.
 * req_do	- pointer to get request doc.
 * object_type	- isns object type.
 * flag		- user options
 *
 * ****************************************************************************
 */
static int
cvt_enumerate_rsp_to_get_req(xmlChar *doc, xmlChar **req_doc,
	object_type obj, uint32_t flag)
{
	xmlTextReaderPtr reader;
	xmlChar **argxmlv;
	int ret = 0, status;
	int i, argxmlc = 0, m_flag = 0;

	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory((const char *)doc,
	    xmlStrlen(doc), NULL, NULL, 0)) == NULL) {
	    return (ERROR_XML_READER_NULL);
	}

	/* if status is 0, continue on.  Otherwise return an error. */
	if (reader = lookup_next_matching_elem(reader, &m_flag, STATUSELEMENT,
	    RESULTELEMENT)) {
	    if (m_flag == READER_MATCH) {
		if (xmlTextReaderRead(reader) == 1) {
		    status =
		    atoi((const char *)xmlTextReaderConstValue(reader));
		    if (status != 0) {
			print_error_status(status, obj, reader);
			(void) xmlTextReaderClose(reader);
			(void) xmlFreeTextReader(reader);
			return (status);
		    }
		} else {
		    (void) xmlTextReaderClose(reader);
		    xmlFreeTextReader(reader);
		    return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
		}
	    } else {
		return (ERROR_XML_STATUS_ELEM_NOT_FOUND);
	    }
	} else {
	    return (ERROR_XML_READER_NULL);
	}

	m_flag = 0;

	argxmlv = (xmlChar **)malloc(sizeof (xmlChar *));

	/* XXX - validate isnsResponse element from response doc. */
	switch (obj) {
	    case Node:
		/* process the node elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    NODEOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    }

		    /* check the type */
		    if ((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)TYPEATTR)) == 1) {
			if (((flag & TARGET_ONLY) == TARGET_ONLY) &&
			    (XMLNCMPVAL(reader, TARGETTYPE) != 0)) {
			    /* move to next node object. */
			    (void) xmlTextReaderMoveToElement(reader);
			    (void) xmlTextReaderNext(reader);
			    continue;
			}
			if (((flag & INITIATOR_ONLY) == INITIATOR_ONLY) &&
			    (XMLNCMPVAL(reader, INITIATORTYPE) != 0)) {
			    /* move to next node object. */
			    (void) xmlTextReaderMoveToElement(reader);
			    (void) xmlTextReaderNext(reader);
			    continue;
			}
		    } else {
			ret = ERROR_XML_TYPE_ATTR_NOT_FOUND;
			goto out;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			xmlTextReaderConstValue(reader)) {
			argxmlv = NEW_XMLARGV(argxmlv, argxmlc);
			if (argxmlv == (xmlChar **)NULL) {
			    ret = ERROR_MALLOC_FAILED;
			    goto out;
			}
			argxmlv[argxmlc++] =
			    xmlStrdup(xmlTextReaderConstValue(reader));
			argxmlv[argxmlc] = NULL;
		    } else {
			ret = ERROR_XML_NAME_ATTR_NOT_FOUND;
			goto out;
		    }
		    (void) xmlTextReaderRead(reader);
		    m_flag = 0;
		} /* end for node while */
		break;
	    case DiscoveryDomain:
		/* process the DiscoveryDoamin elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			xmlTextReaderConstValue(reader)) {
			argxmlv = NEW_XMLARGV(argxmlv, argxmlc);
			if (argxmlv == (xmlChar **)NULL) {
			    ret = ERROR_MALLOC_FAILED;
			    goto out;
			}
			argxmlv[argxmlc++] =
			    xmlStrdup(xmlTextReaderConstValue(reader));
			argxmlv[argxmlc] = NULL;
		    } else {
			    ret = ERROR_XML_NAME_ATTR_NOT_FOUND;
			    goto out;
		    }
		    m_flag = 0;
		    (void) xmlTextReaderRead(reader);
		}
		break;
	    case DiscoveryDomainSet:
		/* process the DiscoveryDoaminSet elements */
		while (reader = lookup_next_matching_elem(reader, &m_flag,
		    DDSETOBJECT, ISNSRESPONSE)) {
		    if (m_flag == END_READER_MATCH) {
			(void) xmlTextReaderNext(reader);
			break;
		    }

		    if (((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)NAMEATTR)) == 1) &&
			(const char *)xmlTextReaderConstValue(reader)) {
			argxmlv = NEW_XMLARGV(argxmlv, argxmlc);
			if (argxmlv == (xmlChar **)NULL) {
			    ret = ERROR_MALLOC_FAILED;
			    goto out;
			}
			argxmlv[argxmlc++] =
			    xmlStrdup(xmlTextReaderConstValue(reader));
			argxmlv[argxmlc] = NULL;
		    } else {
			ret = ERROR_XML_NAME_ATTR_NOT_FOUND;
			goto out;
		    }
		    m_flag = 0;
		    (void) xmlTextReaderRead(reader);
		}
		break;
	    default:
		ret = UNKNOWN;
		goto out;
	}

	/* if no object found, stop here.  The status can be still 0. */
	if (argxmlc != 0) {
	    if ((ret = build_get_xml_doc(argxmlc, (char **)argxmlv, obj,
		req_doc)) != 0) {
		return (ret);
	    }
	} else {
	    if (ret == 0) {
		/* indicate there is no error but not object is found. */
		ret = SUCCESS_WITH_NO_OBJECT;
	    }
	}

out:
	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);
	if (argxmlc != 0) {
	    for (i = 0; i < argxmlc; i++) {
		xmlFree(argxmlv[i]);
	    }
	    (void) free(argxmlv);
	}
	return (ret);

}

/*
 * ****************************************************************************
 *
 * build_delete_xml_doc -
 *	build remove request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * name		- object type
 * assoc	- association type
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_delete_xml_doc(int operandLen, char **operand, object_type obj,
	char *container, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int i, len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	if ((xmlTextWriterWriteAttribute(writer,
	    (xmlChar *)XMLNSATTR, (xmlChar *)XMLNSATTRVAL)) < 0) {
	    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
	}

	/* request delete operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)DELETE) < 0) {
		return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case DiscoveryDomain:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i])) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomain". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainSet:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery DomainSet element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainSet". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainMember:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain Member element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECTMEMBER) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "DD Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDNAMEATTR, (xmlChar *)container) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* Start attr "Node Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NODENAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainMember. */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainSetMember:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain Member element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECTMEMBER) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "DD Set Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDSETNAMEATTR, (xmlChar *)(container)) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* Start attr "DD Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDNAMEATTR, (xmlChar *)(operand[i])) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainSetMember. */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    default:
		    xmlFreeTextWriter(writer);
		    return (UNKNOWN);
	}

	/* end createModify */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);

	return (0);
}

/*
 * ****************************************************************************
 *
 * build_modify_xml_doc -
 *	build create request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * operannLen	- number of objects
 * operand	- object list
 * enabled	- indication of enable and disable boolean type element.
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_modify_xml_doc(int operandLen, char **operand, object_type obj,
	boolean_t enabled, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int i, len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	if ((xmlTextWriterWriteAttribute(writer,
	    (xmlChar *)XMLNSATTR, (xmlChar *)XMLNSATTRVAL)) < 0) {
	    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
	}

	/* request createModify operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)CREATEMODIFY) < 0) {
		return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case DiscoveryDomain:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* write attr "name". */
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i])) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* write bootlist_enabled elem */
		    if (xmlTextWriterWriteElement(writer,
			(xmlChar *)BOOTLISTENABLEDELEM, (enabled)?
			(xmlChar *)XMLTRUE : (xmlChar *)XMLFALSE) < 0) {
			return (ERROR_XML_WRITE_ELEMENT_FAILED);
		    }

		    /* End element "DiscoveryDomain". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainSet:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery DomainSet element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* write enabled elem */
		    if (xmlTextWriterWriteElement(writer,
			(xmlChar *)ENABLEDELEM, (enabled) ?
			(xmlChar *)XMLTRUE : (xmlChar *)XMLFALSE) < 0) {
			return (ERROR_XML_WRITE_ELEMENT_FAILED);
		    }

		    /* End element "DiscoveryDomainSet". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    default:
		    xmlFreeTextWriter(writer);
		    return (UNKNOWN);
	}

	/* end createModify */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);

	return (0);
}

/*
 * ****************************************************************************
 *
 * build_rename_xml_doc -
 *	build create request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * assoc	- a new name
 * id		- index of the object of which name  to be changed
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_rename_xml_doc(char *name, object_type obj, uint32_t id, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int len;
	char namebuf[32];

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	if ((xmlTextWriterWriteAttribute(writer,
	    (xmlChar *)XMLNSATTR, (xmlChar *)XMLNSATTRVAL)) < 0) {
	    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
	}

	/* request createModify operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)CREATEMODIFY) < 0) {
		return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case DiscoveryDomain:
		    /* start Discovery Domain element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* write attr "name". */
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)name)) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* write attr "id". */
		    (void) sprintf(namebuf, "%d", id);
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)IDATTR, (xmlChar *)namebuf)) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomain". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		break;
	    case DiscoveryDomainSet:
		    /* start Discovery DomainSet element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)name) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* write attr "id". */
		    (void) sprintf(namebuf, "%d", id);
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)IDATTR, (xmlChar *)namebuf)) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainSet". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		break;
	    default:
		    xmlFreeTextWriter(writer);
		    return (UNKNOWN);
	}

	/* end createModify */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);

	return (0);
}

/*
 * ****************************************************************************
 *
 * build_create_xml_doc -
 *	build create request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * name		- object type
 * assoc	- association type
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_create_xml_doc(int operandLen, char **operand, object_type obj,
	char *container, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int i, len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	/* request createModify operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)CREATEMODIFY) < 0) {
		return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case DiscoveryDomain:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if ((xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i])) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomain". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainSet:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery DomainSet element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainSet". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainMember:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain Member element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDOBJECTMEMBER) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "DD Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDNAMEATTR, (xmlChar *)container) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* Start attr "Node Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NODENAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainMember. */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case DiscoveryDomainSetMember:
		for (i = 0; i < operandLen; i++) {
		    /* start Discovery Domain Member element. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)DDSETOBJECTMEMBER) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "DD Set Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDSETNAMEATTR, (xmlChar *)(container)) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* Start attr "DD Name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)DDNAMEATTR, (xmlChar *)(operand[i])) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "DiscoveryDomainSetMember. */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    default:
		    xmlFreeTextWriter(writer);
		    return (UNKNOWN);
	}

	/* end createModify */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    xmlFreeTextWriter(writer);
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);

	return (0);
}

/*
 * ****************************************************************************
 *
 * build_assoc_xml_doc -
 *	build association request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * name		- object type
 * assoc	- association type
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_assoc_xml_doc(xmlChar *name, association_t assoc, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	/* request getAssociated operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)GETASSOCIATED) < 0) {
		return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (assoc) {
	    case (node_to_dd):
		/* write association type. */
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ASSOCIATIONTYPE,
		    (xmlChar *)DDOBJECTMEMBER) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}

		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)ISNSOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)NODEOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* Start attr "name". */
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)NAMEATTR, name) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)TYPEATTR, (xmlChar *)EMPTYSTR) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)ALIASATTR, (xmlChar *)EMPTYSTR) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}

		/* End element "Node". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}

		/* End element "isnsObject". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}
		break;
	    case (dd_to_node):
		/* write association type. */
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ASSOCIATIONTYPE,
		    (xmlChar *)DDOBJECTMEMBER) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}

		/* start isnsObject */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)ISNSOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* start DiscoveryDomain */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)DDOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* Start attr "name". */
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)NAMEATTR, name) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}

		/* End element "DiscoveryDomain". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}

		/* End element "isnsObject". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}
		break;
	    case (ddset_to_dd):
		/* write association type. */
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ASSOCIATIONTYPE,
		    (xmlChar *)DDSETOBJECTMEMBER) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}

		/* start isnsObject */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)ISNSOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* start DiscoveryDomainSet */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)DDSETOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* Start attr "name". */
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)NAMEATTR, name) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}

		/* End element "DiscoveryDomain". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}

		/* End element "isnsObject". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}
		break;
	    case (dd_to_ddset):
		/* write association type. */
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ASSOCIATIONTYPE,
		    (xmlChar *)DDSETOBJECTMEMBER) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}

		/* start isnsObject */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)ISNSOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* start DiscoveryDomain */
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)DDOBJECT) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}

		/* Start attr "name". */
		if (xmlTextWriterWriteAttribute(writer,
		    (xmlChar *)NAMEATTR, name) < 0) {
		    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		}

		/* End element "DiscoveryDomain". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}

		/* End element "isnsObject". */
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}
		break;
	    default:
		return (UNKNOWN);
	}

	/* end getAssociated */
	if (xmlTextWriterEndElement(writer) < 0) {
		return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);
	return (0);
}

/*
 * ****************************************************************************
 *
 * build_enumerate_xml_doc -
 *	build association request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * name		- object type
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_enumerate_xml_doc(object_type obj, xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	/* Start attr "xmlns". */
	if (xmlTextWriterWriteAttribute(writer,
	    (xmlChar *)"xmlns",
	    (xmlChar *)"http://www.sun.com/schema/isnsmanagement")) {
	    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
	}

	/* request enumerate operation to get the entire list of obejct. */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ENUMERATE) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case (Node):
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ISNSOBJECTTYPE, (xmlChar *)NODEOBJECT) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}
		break;
	    case (DiscoveryDomain):
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ISNSOBJECTTYPE,
		    (xmlChar *)DDOBJECT) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}
		break;
	    case (DiscoveryDomainSet):
		if (xmlTextWriterWriteElement(writer,
		    (xmlChar *)ISNSOBJECTTYPE,
		    (xmlChar *)DDSETOBJECT) < 0) {
		    return (ERROR_XML_WRITE_ELEMENT_FAILED);
		}
		break;
	    default:
		return (UNKNOWN);
	}

	/* end isns object type */
	if (xmlTextWriterEndElement(writer) < 0) {
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}

	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);
	return (0);
}

/*
 * ****************************************************************************
 *
 * build_get_xml_doc -
 *	build association request doc based the name.
 *	the resulted doc is passed in the doc ptr.
 *
 * name		- object type
 * assoc	- association type
 * doc		- ptr to the resulted doc
 *
 * ****************************************************************************
 */
static int
build_get_xml_doc(int operandLen, char **operand, object_type obj,
	xmlChar **doc)
{
	xmlTextWriterPtr writer;
	xmlBufferPtr xbuf;
	int i, len;

	if ((xbuf = xmlBufferCreate()) == NULL) {
		return (ERROR_XML_CREATE_BUFFER_FAILED);
	}

	if ((writer = xmlNewTextWriterMemory(xbuf, 0)) == NULL) {
		return (ERROR_XML_CREATE_WRITER_FAILED);
	}

	if (xmlTextWriterStartDocument(writer, "1.0", NULL, NULL) < 0) {
		return (ERROR_XML_START_DOC_FAILED);
	}

	/* Start element "isnsRequest". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)ISNSREQUEST) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	/* Start attr "xmlns". */
	if (xmlTextWriterWriteAttribute(writer,
	    (xmlChar *)"xmlns",
	    (xmlChar *)"http://www.sun.com/schema/isnsmanagement")) {
	    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
	}

	/* Start element "get". */
	if (xmlTextWriterStartElement(writer, (xmlChar *)GET) < 0) {
	    return (ERROR_XML_START_ELEMENT_FAILED);
	}

	switch (obj) {
	    case (Node):
		for (i = 0; i < operandLen; i++) {
		    /* Start element "isnsObject". */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)ISNSOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start element Node. */
		    if (xmlTextWriterStartElement(writer,
			(xmlChar *)NODEOBJECT) < 0) {
			return (ERROR_XML_START_ELEMENT_FAILED);
		    }

		    /* Start attr "name". */
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)TYPEATTR, (xmlChar *)EMPTYSTR) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }
		    if (xmlTextWriterWriteAttribute(writer,
			(xmlChar *)ALIASATTR, (xmlChar *)EMPTYSTR) < 0) {
			return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
		    }

		    /* End element "Node". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }

		    /* End element "isnsObject". */
		    if (xmlTextWriterEndElement(writer) < 0) {
			return (ERROR_XML_END_ELEMENT_FAILED);
		    }
		}
		break;
	    case (DiscoveryDomain):
		    for (i = 0; i < operandLen; i++) {
			/* Start element "isnsObject". */
			if (xmlTextWriterStartElement(writer,
			    (xmlChar *)ISNSOBJECT) < 0) {
			    return (ERROR_XML_START_ELEMENT_FAILED);
			}

			if (xmlTextWriterStartElement(writer,
			    (xmlChar *)DDOBJECT) < 0) {
			    return (ERROR_XML_START_ELEMENT_FAILED);
			}

			/* Start attr "name". */
			if (xmlTextWriterWriteAttribute(writer,
			    (xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
			}

			/* End element "DiscoveryDomain". */
			if (xmlTextWriterEndElement(writer) < 0) {
			    return (ERROR_XML_END_ELEMENT_FAILED);
			}

			/* End element "isnsObject". */
			if (xmlTextWriterEndElement(writer) < 0) {
			    return (ERROR_XML_END_ELEMENT_FAILED);
			}
		    }
		    break;
	    case (DiscoveryDomainSet):
		    for (i = 0; i < operandLen; i++) {
			/* Start element "isnsObject". */
			if (xmlTextWriterStartElement(writer,
			    (xmlChar *)ISNSOBJECT) < 0) {
			    return (ERROR_XML_START_ELEMENT_FAILED);
			}

			if (xmlTextWriterStartElement(writer,
			    (xmlChar *)DDSETOBJECT) < 0) {
			    return (ERROR_XML_START_ELEMENT_FAILED);
			}

			/* Start attr "name". */
			if (xmlTextWriterWriteAttribute(writer,
			    (xmlChar *)NAMEATTR, (xmlChar *)operand[i]) < 0) {
			    return (ERROR_XML_WRITE_ATTRIBUTE_FAILED);
			}

			/* End element "DiscoveryDomain". */
			if (xmlTextWriterEndElement(writer) < 0) {
			    return (ERROR_XML_END_ELEMENT_FAILED);
			}

			/* End element "isnsObject". */
			if (xmlTextWriterEndElement(writer) < 0) {
			    return (ERROR_XML_END_ELEMENT_FAILED);
			}
		    }
		    break;
	    case (ServerConfig):
		if (xmlTextWriterStartElement(writer,
		    (xmlChar *)ISNSSERVER) < 0) {
		    return (ERROR_XML_START_ELEMENT_FAILED);
		}
		if (xmlTextWriterEndElement(writer) < 0) {
		    return (ERROR_XML_END_ELEMENT_FAILED);
		}
		break;
	    default:
	    return (UNKNOWN);
	}

	/* End element "get". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	/* End element "isnsRequest". */
	if (xmlTextWriterEndElement(writer) < 0) {
	    return (ERROR_XML_END_ELEMENT_FAILED);
	}
	if (xmlTextWriterEndDocument(writer) < 0) {
	    return (ERROR_XML_END_DOC_FAILED);
	}

	xmlFreeTextWriter(writer);

	len = xmlStrlen(xbuf->content) + 1;
	/* XXX - copy NULL at the end by having one more extra byte */
	if ((*doc = xmlStrndup(xbuf->content, len)) == NULL) {
	    return (ERROR_XML_STRDUP_FAILED);
	}

	xmlBufferFree(xbuf);
	return (0);
}

/*
 * ****************************************************************************
 *
 * list_node_func -
 * 	isnsadm list-node [options] [<node name>, ...]
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
list_node_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{

	cmdOptions_t *optionList = options;
	xmlChar *doc, *e_doc;
	int ret;
	door_arg_t		darg;
	int			fd, flag = 0;

	for (; optionList->optval; optionList++) {
	    switch (optionList->optval) {
		case 'i':
		    flag |= INITIATOR_ONLY;
		    break;
		case 't':
		    flag |= TARGET_ONLY;
		    break;
		case 'v':
		    flag |= VERBOSE;
		    break;
		default:
		    return (UNKNOWN);
	    }
	}

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	/* No operand specified. Issue enumerate. */
	if (operandLen == 0) {
	    ret = build_enumerate_xml_doc(Node, &doc);
	    if (ret != 0) {
		(void) close(fd);
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		return (ret);
	    }
	    bzero(&darg, sizeof (darg));
	    darg.data_ptr = (char *)doc;
	    darg.data_size = xmlStrlen(doc) + 1;
	    darg.rbuf = NULL;
	    darg.rsize = 0;

	    if ((flag & VERBOSE) == VERBOSE) {
		if ((door_call(fd, &darg)) == -1) {
		    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
		    (void) close(fd);
		    (void) xmlFree(doc);
		    return (ret);
		}

		if ((ret = cvt_enumerate_rsp_to_get_req((xmlChar *)darg.rbuf,
		    &e_doc, Node, flag)) != 0) {
		    (void) munmap(darg.rbuf, darg.rsize);
		    (void) close(fd);
		    (void) xmlFree(doc);
		    if (ret != SUCCESS_WITH_NO_OBJECT) {
			(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		    } else {
			ret = SUBCOMMAND_SUCCESS;
		    }
		    return (ret);
		} else {
		    (void) munmap(darg.rbuf, darg.rsize);
		    (void) xmlFree(doc);
		    doc = e_doc;
		    bzero(&darg, sizeof (door_arg_t));
		    darg.data_ptr = (char *)doc;
		    darg.data_size = xmlStrlen(doc) + 1;
		    darg.rbuf = NULL;
		    darg.rsize = 0;
		}
	    }
	} else {
	    if ((ret = build_get_xml_doc(operandLen, operand, Node, &doc)) ==
		0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	    } else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		(void) xmlFree(doc);
		return (ret);
	    }
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	if ((ret = process_get_response(Node, (xmlChar *)darg.rbuf, flag)) !=
	    0) {
	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) xmlFree(doc);
	    (void) close(fd);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * list_dd_func -
 * 	isnsadm list-dd [options] [<dd name>, ...]
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
list_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	cmdOptions_t *optionList = options;
	xmlChar *doc, *e_doc;
	int ret;
	door_arg_t		darg;
	int			fd, flag = 0;

	for (; optionList->optval; optionList++) {
	    switch (optionList->optval) {
		case 'v':
		    flag |= VERBOSE;
		    break;
	    }
	}

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	/* No operand specified. Issue enumerate. */
	if (operandLen == 0) {
	    ret = build_enumerate_xml_doc(DiscoveryDomain, &doc);
	    if (ret != 0) {
		(void) close(fd);
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		return (ret);
	    }
	    /* get the enumerate resposne first. */
	    bzero(&darg, sizeof (darg));
	    darg.data_ptr = (char *)doc;
	    darg.data_size = xmlStrlen(doc) + 1;
	    darg.rbuf = NULL;
	    darg.rsize = 0;
	    if ((door_call(fd, &darg)) == -1) {
		ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
		(void) close(fd);
		(void) xmlFree(doc);
		return (ret);
	    }
	    if ((ret = cvt_enumerate_rsp_to_get_req((xmlChar *)darg.rbuf,
		&e_doc, DiscoveryDomain, flag)) != 0) {
		(void) munmap(darg.rbuf, darg.rsize);
		(void) close(fd);
		(void) xmlFree(doc);
		if (ret != SUCCESS_WITH_NO_OBJECT) {
		    (void) fprintf(stderr, "%s\n", getTextMessage(ret));
		} else {
		    ret = SUBCOMMAND_SUCCESS;
		}
		return (ret);
	    } else {
		(void) munmap(darg.rbuf, darg.rsize);
		(void) xmlFree(doc);
		doc = e_doc;
	    }
	} else {
	    if ((ret = build_get_xml_doc(operandLen, operand,
		DiscoveryDomain, &doc)) != 0) {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		(void) xmlFree(doc);
		return (ret);
	    }
	}

	bzero(&darg, sizeof (darg));
	darg.data_ptr = (char *)doc;
	darg.data_size = xmlStrlen(doc) + 1;
	darg.rbuf = NULL;
	darg.rsize = 0;

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	if ((ret = process_get_response(DiscoveryDomain, (xmlChar *)darg.rbuf,
	    flag)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);

	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * list_ddset_func -
 * 	isnsadm list-dd-set [options] [<dd set name>, ...]
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
list_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	cmdOptions_t *optionList = options;
	xmlChar *doc, *e_doc;
	msg_code_t ret;
	door_arg_t		darg;
	int			fd, flag = 0;

	for (; optionList->optval; optionList++) {
	    switch (optionList->optval) {
		case 'v':
		    flag |= VERBOSE;
		    break;
	    }
	}

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	/* No operand specified. Issue enumerate. */
	if (operandLen == 0) {
	    ret = build_enumerate_xml_doc(DiscoveryDomainSet, &doc);
	    if (ret != 0) {
		(void) close(fd);
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		return (ret);
	    }
	    /* get the enumerate resposne. */
	    bzero(&darg, sizeof (darg));
	    darg.data_ptr = (char *)doc;
	    darg.data_size = xmlStrlen(doc) + 1;
	    darg.rbuf = NULL;
	    darg.rsize = 0;
	    if ((door_call(fd, &darg)) == -1) {
		ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
		(void) close(fd);
		(void) xmlFree(doc);
		return (ret);
	    }

	    if ((ret = cvt_enumerate_rsp_to_get_req((xmlChar *)darg.rbuf,
		&e_doc, DiscoveryDomainSet, flag)) != 0) {
		(void) munmap(darg.rbuf, darg.rsize);
		(void) close(fd);
		(void) xmlFree(doc);
		if (ret != SUCCESS_WITH_NO_OBJECT) {
		    (void) fprintf(stderr, "%s\n", getTextMessage(ret));
		} else {
		    ret = SUBCOMMAND_SUCCESS;
		}
		return (ret);
	    } else {
		(void) munmap(darg.rbuf, darg.rsize);
		(void) xmlFree(doc);
		doc = e_doc;
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	    }
	} else {
	    if ((ret = build_get_xml_doc(operandLen, operand,
		DiscoveryDomainSet, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	    } else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
	    }
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_get_response(DiscoveryDomainSet,
	    (xmlChar *)darg.rbuf, flag)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	(void) xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * create_dd_func -
 * 	create a DiscoveryDomain create-dd <dd name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
create_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t		darg;
	int			fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_create_xml_doc(operandLen, operand,
		DiscoveryDomain, NULL, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) close(fd);
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomain)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * create_ddset_func -
 * 	create a DiscoveryDomainSet create-dd-set <dd set name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
create_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
    void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t		darg;
	int			fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_create_xml_doc(operandLen, operand,
		DiscoveryDomainSet, NULL, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSet)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);

	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * modify_dd_func -
 * 	Modify a dd attr. currently rename function is supported
 *	modify-dd -n name <dd name>
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
modify_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	xmlTextReaderPtr reader;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd, m_flag = 0;
	uint32_t    id;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_get_xml_doc(operandLen, operand,
		DiscoveryDomain, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/* Free the request that is created by xmlStrnDup. */
	(void) xmlFree(doc);

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomain)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    return (ret);
	}

	/* setup xml parser on the response. */
	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory
	    ((const char *)darg.rbuf, xmlStrlen((xmlChar *)darg.rbuf),
	    NULL, NULL, 0)) == NULL) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    return (ERROR_XML_READER_NULL);
	}

	if (reader = lookup_next_matching_elem(reader, &m_flag, DDOBJECT,
	    ISNSRESPONSE)) {
	    if (m_flag == READER_MATCH) {
		if ((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)IDATTR)) == 1) {
		    id = atoi((const char *)xmlTextReaderConstValue(reader));
		} else {
			(void) xmlTextReaderClose(reader);
			(void) xmlFreeTextReader(reader);
			return (ERROR_XML_ID_ATTR_NOT_FOUND);
		}
	    } else {
		(void) xmlTextReaderClose(reader);
		(void) xmlFreeTextReader(reader);
		return (ERROR_XML_DD_OBJECT_NOT_FOUND);
	    }
	} else {
	    (void) fprintf(stderr, "%s\n",
		getTextMessage(ERROR_XML_READER_NULL));
	    return (ERROR_XML_READER_NULL);
	}

	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);

	if ((ret = build_rename_xml_doc(options->optarg, DiscoveryDomain,
		id, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomain)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * modify_ddset_func -
 * 	Modify a dd attr. currently rename function is supported
 *	modify-dd-set -n name <dd name>
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
modify_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	xmlTextReaderPtr reader;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd, m_flag = 0;
	uint32_t    id;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_get_xml_doc(operandLen, operand,
		DiscoveryDomainSet, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/* Free the request that is created by xmlStrnDup. */
	(void) xmlFree(doc);

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSet)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    return (ret);
	}

	/* setup xml parser on the response. */
	if ((reader = (xmlTextReaderPtr)xmlReaderForMemory
	    ((const char *)darg.rbuf, xmlStrlen((xmlChar *)darg.rbuf),
	    NULL, NULL, 0)) == NULL) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    return (ERROR_XML_READER_NULL);
	}

	if (reader = lookup_next_matching_elem(reader, &m_flag, DDSETOBJECT,
	    ISNSRESPONSE)) {
	    if (m_flag == READER_MATCH) {
		if ((xmlTextReaderMoveToAttribute(reader,
			(const xmlChar *)IDATTR)) == 1) {
		    id = atoi((const char *)xmlTextReaderConstValue(reader));
		} else {
			(void) xmlTextReaderClose(reader);
			(void) xmlFreeTextReader(reader);
			return (ERROR_XML_ID_ATTR_NOT_FOUND);
		}
	    } else {
		(void) xmlTextReaderClose(reader);
		(void) xmlFreeTextReader(reader);
		(void) fprintf(stderr, "%s\n",
		    getTextMessage(ERROR_XML_NAME_ATTR_NOT_FOUND));
		return (ERROR_XML_DD_SET_OBJECT_NOT_FOUND);
	    }
	}

	(void) xmlTextReaderClose(reader);
	(void) xmlFreeTextReader(reader);

	if ((ret = build_rename_xml_doc(options->optarg, DiscoveryDomainSet,
		id, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSet)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * add_node_func -
 * 	Add a node to a DiscoveryDomain add-node -d dd-name <node name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
add_node_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_create_xml_doc(operandLen, operand,
		DiscoveryDomainMember, options->optarg, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainMember)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * add_dd_func -
 * 	Add a dd to a DiscoveryDomainSet add-dd -s dd-set name <dd name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
add_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_create_xml_doc(operandLen, operand,
		DiscoveryDomainSetMember, options->optarg, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSetMember)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * remove_node_func -
 * 	Remove a node from DiscoveryDomain
 *	remov-node -d dd-name <node name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
remove_node_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_delete_xml_doc(operandLen, operand,
		DiscoveryDomainMember, options->optarg, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainMember)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * remove_dd_func -
 * 	Remove a dd from DiscoveryDomainSet
 *	remove-dd -s dd-set name <dd name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
remove_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t	darg;
	int	fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_delete_xml_doc(operandLen, operand,
		DiscoveryDomainSetMember, options->optarg, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSetMember)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * delete_dd_func -
 * 	remove a DiscoveryDomain remove-dd <dd name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
delete_dd_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t		darg;
	int			fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_delete_xml_doc(operandLen, operand,
		DiscoveryDomain, NULL, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomain)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);

	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * delete_ddset_func -
 * 	delete DiscoveryDomainSet(s) delete-dd-set <dd set name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
delete_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
    void *addarg)
{
	xmlChar *doc;
	msg_code_t ret;
	door_arg_t		darg;
	int			fd;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_delete_xml_doc(operandLen, operand,
		DiscoveryDomainSet, NULL, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	/*
	 * door frame work allocated a buffer when the date lager that rbuf.
	 * indicate if munmap is required on rbuf.
	 */
	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSet)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * i_enableddset
 * 	enables/disables DiscoveryDomainSet(s)
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * enable	- indication of enable/disable
 *
 * ****************************************************************************
 */
static int
i_enableddset(int operandLen, char *operand[], boolean_t enable)
{
	xmlChar *doc;
	door_arg_t		darg;
	int fd, ret = 0;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_modify_xml_doc(operandLen, operand,
		DiscoveryDomainSet, enable, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	xmlFree(doc);

	if ((ret = process_result_response((xmlChar *)darg.rbuf,
		DiscoveryDomainSet)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	return (SUBCOMMAND_SUCCESS);
}

/*
 * ****************************************************************************
 *
 * enable_ddset_func -
 * 	enables DiscoveryDomainSet(s) enable-dd-set <dd set name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
enable_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
    void *addarg)
{
	return (i_enableddset(operandLen, operand, B_TRUE));
}

/*
 * ****************************************************************************
 *
 * disabledsetFunc -
 * 	disable DiscoveryDomainSet(s) disable-dd-set <dd set name>, ...
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
disable_ddset_func(int operandLen, char *operand[], cmdOptions_t *options,
    void *addarg)
{
	return (i_enableddset(operandLen, operand, B_FALSE));
}

/*
 * ****************************************************************************
 *
 * show_config_func -
 * 	isnsadm show-config
 *
 * operandLen	- number of operands user passed into the cli
 * operand	- pointer to operand list from user
 * options	- pointer to option list from user
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
static int
show_config_func(int operandLen, char *operand[], cmdOptions_t *options,
	void *addarg)
{
	xmlChar *doc;
	int ret;
	door_arg_t		darg;
	int			fd, flag = 0;

	if ((fd = open(ISNS_DOOR_NAME, 0)) == -1) {
	    ret = check_door_error(ERROR_DOOR_OPEN_FAILED, errno);
	    return (ret);
	}

	if ((ret = build_get_xml_doc(operandLen, operand,
		ServerConfig, &doc)) == 0) {
		bzero(&darg, sizeof (darg));
		darg.data_ptr = (char *)doc;
		darg.data_size = xmlStrlen(doc) + 1;
		darg.rbuf = NULL;
		darg.rsize = 0;
	} else {
		(void) fprintf(stderr, "%s\n", getTextMessage(ret));
		(void) close(fd);
		(void) xmlFree(doc);
		return (ret);
	}

	if ((door_call(fd, &darg)) == -1) {
	    ret = check_door_error(ERROR_DOOR_CALL_FAILED, errno);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	if ((ret = process_get_response(ServerConfig, (xmlChar *)darg.rbuf,
	    flag)) != 0) {
	    (void) munmap(darg.rbuf, darg.rsize);
	    (void) close(fd);
	    (void) xmlFree(doc);
	    return (ret);
	}

	(void) munmap(darg.rbuf, darg.rsize);
	(void) close(fd);
	xmlFree(doc);

	return (SUBCOMMAND_SUCCESS);
}

/*
 * *************************************************************************
 *
 * main
 *
 * *************************************************************************
 */
int
main(int argc, char *argv[])
{
	synTables_t 			synTables;
	char 				versionString[VERSION_STRING_MAX_LEN];
	int 				ret;
	int 				funcRet;
	void 				*subcommandArgs = NULL;

	(void) setlocale(LC_ALL, "");

	(void) sprintf(versionString, "%2s.%2s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subCommandPropsTbl = &subcommands[0];

	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);

	if (ret == 1) {
		return (COMMAND_SYNTAX_FAILED);
	} else if (ret == -1) {
		perror(argv[0]);
		return (1);
	} else if (ret == 0) {
		/*
		 * strawman way to sort out the error code.
		 * isnsi server protocol error range 0 - 99
		 * isns server maangement op error range 100 -199
		 * isnsadm error range 200 -299
		 */
	    if (funcRet == SUBCOMMAND_SUCCESS) {
		return (0);
	    } else if (funcRet > SUBCOMMAND_SUCCESS) {
		if (funcRet != ERROR_DOOR_CALL_FAILED &&
		    funcRet != ERROR_DOOR_OPEN_FAILED) {
		    (void) fprintf(stderr, "%s\n", getTextMessage(funcRet));
		}
		return (1);
	    } else {
		return (1);
	    }
	}

	return (0);
} /* end main */
