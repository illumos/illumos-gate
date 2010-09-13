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
 * isnsadm_msg.c : handles the text message.
 *
 */


#include "isnsadm.h"

char *getTextMessage(msg_code_t code) {
	switch (code) {
		case UNKNOWN:
		    return (gettext("Error: Unknown Failure"));
		case ERROR_PARTIAL_SUCCESS:
		    return (gettext("\nError: one or more objects failed to "
		    "be processed.\nCheck the missing object from the "
		    "response and issue the operation individaully to get "
		    "the specific error information."));
		case ERROR_PARTIAL_FAILURE:
		    return (gettext("Error: one or more objects failed to "
		    "be processed.\nCheck the following failed object "
		    "and issue the operation individaully to get the specific "
		    "error information."));
		case ERROR_NO_ADDITIONAL_PARTIAL_FAILIRE_INFO:
		    return (gettext("No additional information avaialble from "
			"the response."));
		case ERROR_XML_READER_NULL:
		    return (gettext
			("Error: XML reader not set for respone document."));
		case ERROR_XML_RESPONSE_ERROR:
		    return (gettext
			("Error: Failed to get expected XML element."));
		case ERROR_XML_NAME_ATTR_NOT_FOUND:
		    return (gettext
			("Error: Name attribute not found in reponse."));
		case ERROR_XML_ID_ATTR_NOT_FOUND:
		    return (gettext
			("Error: Index attribute not found in reponse."));
		case ERROR_XML_TYPE_ATTR_NOT_FOUND:
		    return (gettext
			("Error: Node type not found in reponse."));
		case ERROR_XML_ALIAS_ATTR_NOT_FOUND:
		    return (gettext
			("Error: Node Alias not found in reponse."));
		case ERROR_XML_DD_OBJECT_NOT_FOUND:
		    return (gettext
		    ("Error: Discovery Domain object not found in reponse."));
		case ERROR_XML_DD_SET_OBJECT_NOT_FOUND:
		    return (gettext
		    ("Error: Discovery Domain Set object not found in "
		    "reponse."));
		case ERROR_XML_STATUS_ELEM_NOT_FOUND:
		    return (gettext
			("Error: Failed to get the status from the server."));
		case ERROR_XML_MESSAGE_ELEM_NOT_FOUND:
		    return (gettext
			("Error: Failed to get the error information."));
		case ERROR_XML_ISNSSERVER_ELEM_NOT_FOUND:
		    return (gettext
			("Error: Config information not found in reponse."));
		case ERROR_XML_CREATE_WRITER_FAILED:
		    return (gettext
			("Error: Failed to create the xml writer."));
		case ERROR_XML_CREATE_BUFFER_FAILED:
		    return (gettext
			("Error: Creating the buffer for XML writer."));
		case ERROR_XML_START_DOC_FAILED:
		    return (gettext
			("Error: Failed to create xml start doc."));
		case ERROR_XML_END_DOC_FAILED:
		    return (gettext
			("Error: Failed to create xml end doc."));
		case ERROR_XML_START_ELEMENT_FAILED:
		    return (gettext
			("Error: Failed to create xml start element."));
		case ERROR_XML_WRITE_ELEMENT_FAILED:
		    return (gettext
			("Error: Failed to create xml write element."));
		case ERROR_XML_END_ELEMENT_FAILED:
		    return (gettext
			("Error: Failed to create xml end element."));
		case ERROR_XML_WRITE_ATTRIBUTE_FAILED:
		    return (gettext
			("Error: Failed to write an xml attribute."));
		case ERROR_XML_STRDUP_FAILED:
		    return (gettext
			("Error: xml strdup failed."));
		case ERROR_XML_PARSE_MEMORY_FAILED:
		    return (gettext
			("Error: xml parse memory failed."));
		case ERROR_XML_XPATH_NEW_CONTEXT_FAILED:
		    return (gettext
			("Error: xml xpath context setup failed."));
		case ERROR_XML_ADD_CHILD_FAILED:
		    return (gettext
			("Error: xml add child failed."));
		case ERROR_DOOR_CALL_FAILED:
		    return (gettext
			("Error: call on the door to send a request to the "
			"server failed."));
		case ERROR_DOOR_OPEN_FAILED:
		    return (gettext
			("Error: open on the door to communicate to the "
			"server failed."));
		case ERROR_ISNS_SMF_SERVICE_NOT_ONLINE:
		    return (gettext
			("Error: network/isns_server smf(5) "
			"service is not online."));
		case ERROR_MALLOC_FAILED:
		    return (gettext
			("Error: memory allocation failed."));
		case ERROR_DDMEMBER_NOT_FOUND:
		    return (gettext
			("Error: no such Discovery Domain membership exist."));
		case ERROR_DDSETMEMBER_NOT_FOUND:
		    return (gettext
			("Error: no such Discovery Domain Set "
			"membership exist."));
		case ERROR_DDMEMBER_ALREADY_EXIST:
		    return (gettext
			("Error: Discovery Domain membership already exist."));
		case ERROR_DDSETMEMBER_ALREADY_EXIST:
		    return (gettext
			("Error: Discovery Domain Set membership "
			"already exist."));
		case ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DD:
		    return (gettext
			("Error: operation not allowed for the Default "
			"Discovery Domain."));
		case ERROR_OPERATION_NOT_ALLOWED_FOR_DEFAULT_DDSET:
		    return (gettext
			("Error: operation not allowed for the Default "
			"Discovery Domain Set."));
		case ERROR_DD_NAME_IN_USE:
		    return (gettext
			("Error: Discovery Domain name already exists."));
		case ERROR_DDSET_NAME_IN_USE:
		    return (gettext
			("Error: Discovery Domain Set name already exist."));
		case ERROR_SERVER_BUSY:
		    return (gettext
			("Error: server reported busy status."));
		case ERROR_SERVER_INTERNAL_ERROR:
		    return (gettext
			("Error: server reported internal error status."));
		default:
		    return (gettext
			("Unknown error."));
	}
}
