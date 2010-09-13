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

#include <libintl.h>

#include "isns_utils.h"
#include "isns_protocol.h"

char *
result_code_to_str(int code)
{
	switch (code) {
	    case ISNS_RSP_SUCCESSFUL:
		return ((char *)gettext("Successful Operation"));
	    case ISNS_RSP_UNKNOWN_ERROR:
		return ((char *)gettext("Unknown Error"));
	    case ISNS_RSP_MSG_FORMAT_ERROR:
		return ((char *)gettext("Message Format Error"));
	    case ISNS_RSP_INVALID_REGIS:
		return ((char *)gettext("Invalid Registration"));
	    case ISNS_RSP_INVALID_QRY:
		return ((char *)gettext("Invalid Query"));
	    case ISNS_RSP_SRC_UNKNOWN:
		return ((char *)gettext("Source Unknown"));
	    case ISNS_RSP_SRC_ABSENT:
		return ((char *)gettext("Source Absent"));
	    case ISNS_RSP_SRC_UNAUTHORIZED:
		return ((char *)gettext("Source Unauthorized"));
	    case ISNS_RSP_NO_SUCH_ENTRY:
		return ((char *)gettext("No Such Entry"));
	    case ISNS_RSP_VER_NOT_SUPPORTED:
		return ((char *)gettext("Version Not Supported"));
	    case ISNS_RSP_INTERNAL_ERROR:
		return ((char *)gettext("Internal Error"));
	    case ISNS_RSP_BUSY:
		return ((char *)gettext("Busy"));
	    case ISNS_RSP_OPTION_NOT_UNDERSTOOD:
		return ((char *)gettext("Option Not Understood"));
	    case ISNS_RSP_INVALID_UPDATE:
		return ((char *)gettext("Invalid Update"));
	    case ISNS_RSP_MSG_NOT_SUPPORTED:
		return ((char *)gettext("Message Not Supported"));
	    case ISNS_RSP_SCN_EVENT_REJECTED:
		return ((char *)gettext("SCN Event Rejected"));
	    case ISNS_RSP_SCN_REGIS_REJECTED:
		return ((char *)gettext("SCN Registration Rejected"));
	    case ISNS_RSP_ATTR_NOT_IMPL:
		return ((char *)gettext("Attribute Not Implemented"));
	    case ISNS_RSP_ESI_NOT_AVAILABLE:
		return ((char *)gettext("ESI Not Available"));
	    case ISNS_RSP_INVALID_DEREGIS:
		return ((char *)gettext("Invalid Deregistration"));
	    case ISNS_RSP_REGIS_NOT_SUPPORTED:
		return ((char *)gettext("Registration Not Supported"));
	    case PARTIAL_SUCCESS:
		return ((char *)gettext("Partial_success"));
	    case PARTIAL_FAILURE:
		return ((char *)gettext("Partial failure"));
	    case ERR_DOOR_ALREADY_RUNNING:
		return ((char *)gettext("iSNS managemnet door is already "
		    "running"));
	    case ERR_DOOR_CREATE_FAILED:
		return ((char *)gettext("Failed to create iSNS managemnet "
		    "door"));
	    case ERR_DOOR_MORE_SPACE:
		return ((char *)gettext("More space needed to return the "
		    "response"));
	    case ERR_INVALID_MGMT_REQUEST:
		return ((char *)gettext("Invalid managmenet request"));
	    case ERR_NULL_XML_MESSAGE:
		return ((char *)gettext("Null XML request"));
	    case ERR_XML_VALID_OPERATION_NOT_FOUND:
		return ((char *)gettext("XML Doc error: no valid operation "
		    "found"));
	    case ERR_XML_VALID_OBJECT_NOT_FOUND:
		return ((char *)gettext("XML Doc error: no valid object "
		    "found"));
	    case ERR_XML_FAIL_TO_CREATE_WRITE_BUFFER:
		return ((char *)gettext("failed to create XML witer buffer."));
	    case ERR_XML_FAIL_TO_GET_WRITEPTR:
		return ((char *)gettext("failed to get XML writer pointer."));
	    case ERR_XML_INIT_READER_FAILED:
		return ((char *)gettext("failed to initialize XML reader."));
	    case ERR_XML_PARSE_MEMORY_FAILED:
		return ((char *)gettext("failed to parse XML doc in memory."));
	    case ERR_XML_FAILED_TO_SET_XPATH_CONTEXT:
		return ((char *)gettext("failed to get XPATH context."));
	    case ERR_XML_FAILED_TO_REGISTER_NAMESPACE:
		return ((char *)gettext("failed to register name space."));
	    case ERR_SYNTAX_MISSING_ROOT:
		return ((char *)gettext("XML Syntax error: "
		    "isnsRequest root element missing"));
	    case ERR_SYNTAX_MISSING_NAME_ATTR:
		return ((char *)gettext("XML Syntax error: missing a required "
		    " name attribute"));
	    case ERR_XML_OP_FAILED:
		return ((char *)gettext("XML operation failed."));
	    case ERR_XML_STRDUP_FAILED:
		return ((char *)gettext("XML strndup operation failed."));
	    case ERR_MALLOC_FAILED:
		return ((char *)gettext("malloc failed."));
	    case ERR_DOOR_SERVER_DETECTED_INVALID_USER:
		return ((char *)gettext("Door server detected invalid user."));
	    case ERR_DOOR_SERVER_DETECTED_NOT_AUTHORIZED_USER:
		return ((char *)gettext("Door server detected unauthorized "
		    "user."));
	    case ERR_MATCHING_ISCSI_NODE_NOT_FOUND:
		return ((char *)gettext("Matching iSCSI Node not found."));
	    case ERR_MATCHING_NETWORK_ENTITY_NOT_FOUND:
		return ((char *)gettext("Network Entity not found."));
	    case ERR_NO_PORTAL_GROUP_FOUND:
		return ((char *)gettext("No Portal Group not found."));
	    case ERR_MATCHING_PORTAL_NOT_FOUND:
		return ((char *)gettext("Matching Portal not found."));
	    case ERR_MATCHING_DD_NOT_FOUND:
		return ((char *)gettext("Matching Discovery Domain not "
		    "found."));
	    case ERR_MATCHING_DDSET_NOT_FOUND:
		return ((char *)gettext("Matching Discovery Domain Set "
		    "not found."));
	    case ERR_NO_ASSOCIATED_DD_FOUND:
		return ((char *)gettext("No associated Discovery Domain "
		    "found."));
	    case ERR_NO_ASSOCIATED_DDSET_FOUND:
		return ((char *)gettext("No associated Discovery Domain Set "
		    "found."));
	    case ERR_NO_SUCH_ASSOCIATION:
		return ((char *)gettext("No such association."));
	    case ERR_ALREADY_ASSOCIATED:
		return ((char *)gettext("Member is already created."));
	    case ERR_NAME_IN_USE:
		return ((char *)gettext("Name is already in use."));
	    case ERR_DOOR_UCRED_FAILED:
		return ((char *)gettext("Failed to acquire user credentials "
		    "of management door caller"));
	    default:
		return ((char *)gettext("Unknown error code"));
	}
}
