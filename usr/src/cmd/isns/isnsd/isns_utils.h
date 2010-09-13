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

#ifndef	_ISNS_UTILS_H
#define	_ISNS_UTILS_H

#include <isns_msgq.h>

#ifdef __cplusplus
extern "C" {
#endif

int setup_mgmt_door(msg_queue_t *);

typedef enum {
	PARTIAL_SUCCESS = 100,
	PARTIAL_FAILURE,
	ERR_DOOR_ALREADY_RUNNING,
	ERR_DOOR_CREATE_FAILED,
	ERR_DOOR_MORE_SPACE,
	ERR_NULL_XML_MESSAGE,
	ERR_INVALID_MGMT_REQUEST,
	ERR_XML_VALID_OPERATION_NOT_FOUND,
	ERR_XML_VALID_OBJECT_NOT_FOUND,
	ERR_XML_FAIL_TO_CREATE_WRITE_BUFFER,
	ERR_XML_FAIL_TO_GET_WRITEPTR,
	ERR_XML_INIT_READER_FAILED,
	ERR_XML_PARSE_MEMORY_FAILED,
	ERR_XML_FAILED_TO_SET_XPATH_CONTEXT,
	ERR_XML_FAILED_TO_REGISTER_NAMESPACE,
	ERR_XML_NEWNODE_FAILED,
	ERR_XML_ADDCHILD_FAILED,
	ERR_XML_SETPROP_FAILED,
	ERR_XML_NEWCHILD_FAILED,
	ERR_SYNTAX_MISSING_ROOT,
	ERR_SYNTAX_MISSING_NAME_ATTR,
	ERR_MALLOC_FAILED,
	ERR_XML_OP_FAILED,
	ERR_XML_STRDUP_FAILED,
	ERR_DOOR_SERVER_DETECTED_INVALID_USER,
	ERR_DOOR_SERVER_DETECTED_NOT_AUTHORIZED_USER,
	ERR_MATCHING_ISCSI_NODE_NOT_FOUND,
	ERR_MATCHING_NETWORK_ENTITY_NOT_FOUND,
	ERR_NO_PORTAL_GROUP_FOUND,
	ERR_MATCHING_PORTAL_NOT_FOUND,
	ERR_MATCHING_NODE_NOT_FOUND,
	ERR_MATCHING_DD_NOT_FOUND,
	ERR_MATCHING_DDSET_NOT_FOUND,
	ERR_NO_ASSOCIATED_DD_FOUND,
	ERR_NO_ASSOCIATED_DDSET_FOUND,
	ERR_NO_SUCH_ASSOCIATION,
	ERR_ALREADY_ASSOCIATED,
	ERR_NAME_IN_USE,
	ERR_DOOR_UCRED_FAILED
} result_code_t;

char *result_code_to_str(int);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_UTILS_H */
